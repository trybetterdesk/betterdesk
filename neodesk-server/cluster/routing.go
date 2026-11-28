package cluster

import (
	"context"
	"net"
	"time"
)

// DeviceRouting is what the API server needs to pass a device request to
// the pod that holds the device (api.DeviceRouting): the device registry,
// the mesh and the KV for single-use nonces.
type DeviceRouting struct {
	Devices *Devices
	Mesh    *Mesh
	KV      KV
}

func (d DeviceRouting) Owner(ctx context.Context, kind, id string) string {
	return d.Devices.Owner(ctx, kind, id)
}

func (d DeviceRouting) Stream(ctx context.Context, pod, name string, meta map[string]string) (net.Conn, error) {
	return d.Mesh.Stream(ctx, pod, name, meta)
}

func (d DeviceRouting) Call(ctx context.Context, pod, name string, body []byte) ([]byte, error) {
	return d.Mesh.Call(ctx, pod, name, body)
}

// ClaimOnce keeps each nonce for longer than a signature is valid, so a
// replayed stream is refused.
func (d DeviceRouting) ClaimOnce(ctx context.Context, nonce string) bool {
	if len(nonce) < 16 {
		return false
	}
	_, set, err := d.KV.SetNX(ctx, "mesh:nonce:"+nonce, "1", 2*time.Minute)
	return err == nil && set
}
