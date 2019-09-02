package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/go-cni"
	"github.com/opencontainers/image-spec/identity"
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
	maxUid := uint32(MustGetMaxValidUID())
	maxGid := uint32(MustGetMaxValidUID())

	client, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		return err
	}
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), "concourse")

	// image, err := importImage(ctx, client, "oci-build-task.tar")
	image, err := client.Pull(ctx, "docker.io/vito/oci-build-task:latest", containerd.WithPullUnpack)
	// image, err := client.Pull(ctx, "docker.io/vito/containerd-test:latest", containerd.WithPullUnpack)
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
		withRemappedSnapshotBase("some-container-snapshot", image, maxUid, maxGid, false),
		// containerd.WithNewSnapshot("some-container-snapshot", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),

			// carry over garden defaults
			oci.WithDefaultUnixDevices,
			oci.WithLinuxDevice("/dev/fuse", "rwm"),

			// minimum required caps for running buildkit
			oci.WithAddedCapabilities([]string{
				"CAP_SYS_ADMIN",
				"CAP_NET_ADMIN",
			}),

			// enable user namespaces
			oci.WithLinuxNamespace(specs.LinuxNamespace{
				Type: specs.UserNamespace,
			}),
			withRemappedRoot(maxUid, maxGid),

			// ...just set a hostname
			oci.WithHostname("concourse"),

			// wire up concourse stuff
			oci.WithMounts(mounts),
			oci.WithProcessCwd("/inputs"),
			// oci.WithUIDGID(0, 0), // disable rootless for now
			// oci.WithProcessArgs("task"),
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

	info, err := container.Info(ctx)
	if err != nil {
		return err
	}

	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStreams(bytes.NewBuffer(reqBuf), os.Stdout, os.Stderr)), func(_ context.Context, client *containerd.Client, r *containerd.TaskInfo) error {
		var copts interface{}
		container.Info(ctx)
		if containerd.CheckRuntime(info.Runtime.Name, "io.containerd.runc") {
			copts = &options.Options{
				IoUid: maxUid,
				IoGid: maxGid,
			}
		} else {
			copts = &runctypes.CreateOptions{
				IoUid: maxUid,
				IoGid: maxGid,
			}
		}

		r.Options = copts
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

	// XXX: work around lack of reliable cleanup during dev
	_ = network.Remove(ctx, "some-network", "")

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

func withRemappedRoot(maxUid, maxGid uint32) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Linux.UIDMappings = []specs.LinuxIDMapping{
			{
				ContainerID: 0,
				HostID:      maxUid,
				Size:        1,
			},
			{
				ContainerID: 1,
				HostID:      1,
				Size:        maxUid - 1,
			},
		}

		s.Linux.GIDMappings = []specs.LinuxIDMapping{
			{
				ContainerID: 0,
				HostID:      maxGid,
				Size:        1,
			},
			{
				ContainerID: 1,
				HostID:      1,
				Size:        maxGid - 1,
			},
		}

		return nil
	}
}
func withRemappedSnapshotBase(id string, i containerd.Image, uid, gid uint32, readonly bool) containerd.NewContainerOpts {
	return func(ctx context.Context, client *containerd.Client, c *containers.Container) error {
		diffIDs, err := i.RootFS(ctx)
		if err != nil {
			return err
		}

		var (
			parent   = identity.ChainID(diffIDs).String()
			usernsID = fmt.Sprintf("%s-%d-%d", parent, uid, gid)
		)

		c.Snapshotter, err = resolveSnapshotterName(client, ctx, c.Snapshotter)
		if err != nil {
			return err
		}

		snapshotter := client.SnapshotService(c.Snapshotter)

		if _, err := snapshotter.Stat(ctx, usernsID); err == nil {
			if _, err := snapshotter.Prepare(ctx, id, usernsID); err == nil {
				c.SnapshotKey = id
				c.Image = i.Name()
				return nil
			} else if !errdefs.IsNotFound(err) {
				return err
			}
		}

		mounts, err := snapshotter.Prepare(ctx, usernsID+"-remap", parent)
		if err != nil {
			return err
		}
		if err := remapRootFS(ctx, mounts, uid, gid); err != nil {
			snapshotter.Remove(ctx, usernsID)
			return err
		}
		if err := snapshotter.Commit(ctx, usernsID, usernsID+"-remap"); err != nil {
			return err
		}
		if readonly {
			_, err = snapshotter.View(ctx, id, usernsID)
		} else {
			_, err = snapshotter.Prepare(ctx, id, usernsID)
		}
		if err != nil {
			return err
		}
		c.SnapshotKey = id
		c.Image = i.Name()
		return nil
	}
}

func resolveSnapshotterName(c *containerd.Client, ctx context.Context, name string) (string, error) {
	if name == "" {
		label, err := c.GetLabel(ctx, defaults.DefaultSnapshotterNSLabel)
		if err != nil {
			return "", err
		}

		if label != "" {
			name = label
		} else {
			name = containerd.DefaultSnapshotter
		}
	}

	return name, nil
}

func remapRootFS(ctx context.Context, mounts []mount.Mount, uid, gid uint32) error {
	return mount.WithTempMount(ctx, mounts, func(root string) error {
		return filepath.Walk(root, remapRoot(root, uid, gid))
	})
}

func remapRoot(root string, toUid, toGid uint32) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		stat := info.Sys().(*syscall.Stat_t)

		var remap bool

		uid := stat.Uid
		if uid == 0 {
			remap = true
			uid = toUid
		}

		gid := stat.Gid
		if gid == 0 {
			remap = true
			gid = toGid
		}

		if !remap {
			return nil
		}

		// be sure the lchown the path as to not de-reference the symlink to a host file
		return os.Lchown(path, int(uid), int(gid))
	}
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

type IDMap string

const DefaultUIDMap IDMap = "/proc/self/uid_map"
const DefaultGIDMap IDMap = "/proc/self/gid_map"

const maxInt = int(^uint(0) >> 1)

func MustGetMaxValidUID() int {
	return must(DefaultUIDMap.MaxValid())
}

func MustGetMaxValidGID() int {
	return must(DefaultGIDMap.MaxValid())
}

func (u IDMap) MaxValid() (int, error) {
	f, err := os.Open(string(u))
	if err != nil {
		return 0, err
	}

	var m uint
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var container, host, size uint
		if _, err := fmt.Sscanf(scanner.Text(), "%d %d %d", &container, &host, &size); err != nil {
			return 0, ParseError{Line: scanner.Text(), Err: err}
		}

		m = minUint(maxUint(m, container+size-1), uint(maxInt))
	}

	return int(m), nil
}

func Min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func Max(a, b int) int {
	if a > b {
		return a
	}

	return b
}

func maxUint(a, b uint) uint {
	if a > b {
		return a
	}

	return b
}

func minUint(a, b uint) uint {
	if a < b {
		return a
	}

	return b
}

type ParseError struct {
	Line string
	Err  error
}

func (p ParseError) Error() string {
	return fmt.Sprintf(`%s while parsing line "%s"`, p.Err, p.Line)
}

func must(a int, err error) int {
	if err != nil {
		panic(err)
	}

	return a
}
