package btf

import (
	"errors"
	"math"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/token"
	"github.com/cilium/ebpf/internal/unix"
)

// haveBTF attempts to load a BTF blob containing an Int. It should pass on any
// kernel that supports BPF_BTF_LOAD.
var haveBTF = internal.NewFeatureTest("BTF", func() error {
	// 0-length anonymous integer
	err := probeBTF(&Int{})
	tokenFD := token.GetGlobalToken()
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	// EPERM with a BPF token means the kernel knows about BTF but the token
	// doesn't grant permission - treat as supported for feature detection.
	// Without a token, EPERM is a real permission error and should be reported
	// as not supported.
	if errors.Is(err, unix.EPERM) && tokenFD <= 0 {
		return internal.ErrNotSupported
	}
	return err
}, "4.18")

// haveMapBTF attempts to load a minimal BTF blob containing a Var. It is
// used as a proxy for .bss, .data and .rodata map support, which generally
// come with a Var and Datasec. These were introduced in Linux 5.2.
var haveMapBTF = internal.NewFeatureTest("Map BTF (Var/Datasec)", func() error {
	if err := haveBTF(); err != nil {
		return err
	}

	v := &Var{
		Name: "a",
		Type: &Pointer{(*Void)(nil)},
	}

	err := probeBTF(v)
	tokenFD := token.GetGlobalToken()
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	// EPERM with a BPF token means the kernel knows about this but the token
	// doesn't grant permission - treat as supported for feature detection.
	if errors.Is(err, unix.EPERM) && tokenFD <= 0 {
		return internal.ErrNotSupported
	}
	return err
}, "5.2")

// haveProgBTF attempts to load a BTF blob containing a Func and FuncProto. It
// is used as a proxy for ext_info (func_info) support, which depends on
// Func(Proto) by definition.
var haveProgBTF = internal.NewFeatureTest("Program BTF (func/line_info)", func() error {
	if err := haveBTF(); err != nil {
		return err
	}

	fn := &Func{
		Name: "a",
		Type: &FuncProto{Return: (*Void)(nil)},
	}

	err := probeBTF(fn)
	tokenFD := token.GetGlobalToken()
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	// EPERM with a BPF token means the kernel knows about this but the token
	// doesn't grant permission - treat as supported for feature detection.
	if errors.Is(err, unix.EPERM) && tokenFD <= 0 {
		return internal.ErrNotSupported
	}
	return err
}, "5.0")

var haveFuncLinkage = internal.NewFeatureTest("BTF func linkage", func() error {
	if err := haveProgBTF(); err != nil {
		return err
	}

	fn := &Func{
		Name:    "a",
		Type:    &FuncProto{Return: (*Void)(nil)},
		Linkage: GlobalFunc,
	}

	err := probeBTF(fn)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	return err
}, "5.6")

var haveDeclTags = internal.NewFeatureTest("BTF decl tags", func() error {
	if err := haveBTF(); err != nil {
		return err
	}

	t := &Typedef{
		Name: "a",
		Type: &Int{},
		Tags: []string{"a"},
	}

	err := probeBTF(t)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	return err
}, "5.16")

var haveTypeTags = internal.NewFeatureTest("BTF type tags", func() error {
	if err := haveBTF(); err != nil {
		return err
	}

	t := &TypeTag{
		Type:  &Int{},
		Value: "a",
	}

	err := probeBTF(t)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	return err
}, "5.17")

var haveEnum64 = internal.NewFeatureTest("ENUM64", func() error {
	if err := haveBTF(); err != nil {
		return err
	}

	enum := &Enum{
		Size: 8,
		Values: []EnumValue{
			{"TEST", math.MaxUint32 + 1},
		},
	}

	err := probeBTF(enum)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	return err
}, "6.0")

func probeBTF(typ Type) error {
	b, err := NewBuilder([]Type{typ})
	if err != nil {
		return err
	}

	buf, err := b.Marshal(nil, nil)
	if err != nil {
		return err
	}

	attr := &sys.BtfLoadAttr{
		Btf:     sys.SlicePointer(buf),
		BtfSize: uint32(len(buf)),
	}

	// Use global BPF token if available
	if tokenFD := token.GetGlobalToken(); tokenFD > 0 {
		attr.BtfTokenFd = int32(tokenFD)
		attr.BtfFlags = sys.BPF_F_TOKEN_FD
	}

	fd, err := sys.BtfLoad(attr)

	if err == nil {
		fd.Close()
	}

	return err
}
