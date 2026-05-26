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
	drainingRoutes  map[uint64]drainingRoute
}

type drainingRoute struct {
	drainUntilUnix uint64
}

func NewClientSession() *ClientSession {
	return &ClientSession{}
}

func (s *ClientSession) VerifyRoutePrelude1(in RoutePreludeVerificationInput) ([]byte, error) {
	transcript, err := VerifyRoutePrelude1Signatures(in)
	if err != nil {
		return nil, err
	}
	s.ActivateRoute(in.Prelude1.RouteInstanceID, in.Prelude1.HopIndex)
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

func (s *ClientSession) ActivateRoute(routeInstanceID uint64, hopIndex uint8) {
	s.preludeVerified = true
	s.routeInstanceID = routeInstanceID
	s.hopIndex = hopIndex
	if s.drainingRoutes == nil {
		s.drainingRoutes = make(map[uint64]drainingRoute)
	}
	delete(s.drainingRoutes, routeInstanceID)
}

func (s *ClientSession) RotateRoute(routeInstanceID uint64, hopIndex uint8, nowUnix uint64, drainSeconds uint64) error {
	if !s.preludeVerified {
		return fmt.Errorf("route: no active route to rotate")
	}
	s.purgeDrained(nowUnix)
	if len(s.drainingRoutes) != 0 {
		return fmt.Errorf("route: route rotation already draining")
	}
	if s.routeInstanceID == routeInstanceID {
		return fmt.Errorf("route: duplicate active route instance")
	}
	if s.drainingRoutes == nil {
		s.drainingRoutes = make(map[uint64]drainingRoute)
	}
	if drainSeconds > 0 {
		s.drainingRoutes[s.routeInstanceID] = drainingRoute{
			drainUntilUnix: nowUnix + drainSeconds,
		}
	}
	s.routeInstanceID = routeInstanceID
	s.hopIndex = hopIndex
	return nil
}

func (s *ClientSession) AcceptsRouteInstance(routeInstanceID uint64, nowUnix uint64) bool {
	if !s.preludeVerified {
		return false
	}
	if routeInstanceID == s.routeInstanceID {
		return true
	}
	s.purgeDrained(nowUnix)
	draining, ok := s.drainingRoutes[routeInstanceID]
	return ok && nowUnix < draining.drainUntilUnix
}

func (s *ClientSession) purgeDrained(nowUnix uint64) {
	for routeInstanceID, draining := range s.drainingRoutes {
		if nowUnix >= draining.drainUntilUnix {
			delete(s.drainingRoutes, routeInstanceID)
		}
	}
}
