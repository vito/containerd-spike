package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/go-cni"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	task "github.com/vito/oci-build-task"
)

func main() {
	if err := run(); err != nil {
		logrus.Fatal(err)
	}
}

func run() error {
	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return err
	}
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "concourse")

	// image, err := importImage(ctx, client, "oci-build-task.tar")
	// image, err := client.Pull(ctx, "docker.io/vito/oci-build-task:latest", containerd.WithPullUnpack)
	image, err := client.Pull(ctx, "docker.io/vito/containerd-test:latest", containerd.WithPullUnpack)
	// image, err := client.Pull(ctx, "docker.io/sjourdan/strace:latest", containerd.WithPullUnpack)
	if err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	mounts := []specs.Mount{
		{
			Destination: "/sys/fs/cgroup",
			Type:        "cgroup",
			Source:      "cgroup",
			Options:     []string{"ro", "nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/inputs",
			Type:        "bind",
			Source:      filepath.Join(cwd, "input"),
			Options:     []string{"bind"},
		},
		{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      filepath.Join(cwd, "etc", "resolv.conf"),
			Options:     []string{"rbind", "ro"},
		},
		{
			Destination: "/etc/hosts",
			Type:        "bind",
			Source:      filepath.Join(cwd, "etc", "hosts"),
			Options:     []string{"rbind", "ro"},
		},
	}

	container, err := client.NewContainer(
		ctx,
		"some-container",
		// containerd.WithRemappedSnapshot("some-container-snapshot", image, 100000, 100000),
		containerd.WithNewSnapshot("some-container-snapshot", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),

			// carry over garden defaults
			oci.WithDefaultUnixDevices,
			oci.WithLinuxDevice("/dev/fuse", "rwm"),

			// this should probably be what 'privileged' means
			//
			// enabled so that rootless buildkit's newuidmap works (it's suid)
			oci.WithNewPrivileges,

			// Docker doesn't set up /run, and moby/buildkit:rootless sets up
			// /run/user/1000; don't clobber it
			WithoutRunMount,

			// ...just set a hostname
			oci.WithHostname("concourse"),

			// wire up concourse stuff
			oci.WithMounts(mounts),
			oci.WithProcessCwd("/inputs"),
			oci.WithProcessArgs("task"),
		),
	)
	if err != nil {
		return errors.Wrap(err, "new container")
	}
	defer container.Delete(ctx, containerd.WithSnapshotCleanup)

	reqBuf, err := json.Marshal(task.Request{
		ResponsePath: "/dev/stderr",
	})
	if err != nil {
		return err
	}

	logrus.Info("running task")

	// info, err := container.Info(ctx)
	// if err != nil {
	// 	return err
	// }

	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStreams(bytes.NewBuffer(reqBuf), os.Stdout, os.Stderr)), func(_ context.Context, client *containerd.Client, r *containerd.TaskInfo) error {
		// var copts interface{}
		// if containerd.CheckRuntime(info.Runtime.Name, "io.containerd.runc") {
		// 	copts = &options.Options{
		// 		IoUid: 1000,
		// 		IoGid: 1000,
		// 	}
		// } else {
		// 	copts = &runctypes.CreateOptions{
		// 		IoUid: 1000,
		// 		IoGid: 1000,
		// 	}
		// }

		// r.Options = copts
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "new task")
	}
	defer task.Delete(ctx)

	network, err := cni.New(
		cni.WithPluginDir([]string{"plugins"}),
		cni.WithConfListFile("network.json"),
	)
	if err != nil {
		return err
	}

	netns := fmt.Sprintf("/proc/%d/ns/net", task.Pid())

	// XXX: just to handle breakage
	network.Remove(ctx, "some-network", "")

	_, err = network.Setup(ctx, "some-network", netns)
	if err != nil {
		return errors.Wrap(err, "setup network")
	}

	defer func() {
		// release the IP allocation
		//
		// netns is not provided here; the task has probably exited by this point
		// and the ns is gone if so.
		err := network.Remove(ctx, "some-network", "")
		if err != nil {
			logrus.Warnf("error removing network namespace: %s", err)
		}
	}()

	exitStatusC, err := task.Wait(ctx)
	if err != nil {
		return err
	}

	if err := task.Start(ctx); err != nil {
		return err
	}

	status := <-exitStatusC
	code, exitedAt, err := status.Result()
	if err != nil {
		return err
	}

	logrus.Infof("exited %d at %s", code, exitedAt)

	return nil
}

// WithWriteableCgroupfs makes any cgroup mounts writeable
func WithoutRunMount(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
	for i, m := range s.Mounts {
		if m.Destination == "/run" {
			s.Mounts = append(s.Mounts[:i], s.Mounts[i+1:]...)
		}
	}
	return nil
}

func importImage(ctx context.Context, client *containerd.Client, path string) (containerd.Image, error) {
	imageFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer imageFile.Close()

	logrus.Info("importing")

	images, err := client.Import(ctx, imageFile, containerd.WithIndexName("some-ref"))
	if err != nil {
		return nil, err
	}

	var image containerd.Image
	for _, i := range images {
		image = containerd.NewImage(client, i)

		err = image.Unpack(ctx, containerd.DefaultSnapshotter)
		if err != nil {
			return nil, err
		}
	}

	logrus.Debug("image ready")

	if image == nil {
		return nil, fmt.Errorf("no image found in archive: %s", path)
	}

	return image, nil
}
