package route

import (
	"fmt"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
)

type ClientSession struct {
	preludeVerified bool
	routeInstanceID uint64
	hopIndex        uint8
}

func NewClientSession() *ClientSession {
	return &ClientSession{}
}

func (s *ClientSession) VerifyRoutePrelude1(in RoutePreludeVerificationInput) ([]byte, error) {
	transcript, err := VerifyRoutePrelude1Signatures(in)
	if err != nil {
		return nil, err
	}
	s.preludeVerified = true
	s.routeInstanceID = in.Prelude1.RouteInstanceID
	s.hopIndex = in.Prelude1.HopIndex
	return transcript, nil
}

func (s *ClientSession) BuildRouteCapsule1(c protocol.RouteCapsule1Plain) (protocol.RouteCapsule1Plain, error) {
	if !s.preludeVerified {
		return protocol.RouteCapsule1Plain{}, fmt.Errorf("route: ROUTE_PRELUDE1 not verified")
	}
	c.MsgType = registry.MsgRouteCapsule1
	c.RouteInstanceID = s.routeInstanceID
	c.HopIndex = s.hopIndex
	return c, nil
}
