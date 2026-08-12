package session

import "time"

type applicationClock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) func() bool
}

type systemApplicationClock struct{}

func (systemApplicationClock) Now() time.Time { return time.Now() }

func (systemApplicationClock) AfterFunc(delay time.Duration, callback func()) func() bool {
	timer := time.AfterFunc(delay, callback)
	return timer.Stop
}

func (a *Application) scheduleWriteDrainLocked() {
	a.writeDrainGeneration++
	if a.writeDrainStop != nil {
		a.writeDrainStop()
		a.writeDrainStop = nil
	}
	if a.terminal != nil || a.writeState.DrainUntil.IsZero() {
		return
	}
	generation := a.writeDrainGeneration
	delay := a.writeState.DrainUntil.Sub(a.clock.Now())
	if delay <= 0 {
		delay = time.Nanosecond
	}
	a.writeDrainStop = a.clock.AfterFunc(delay, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.terminal != nil || generation != a.writeDrainGeneration {
			return
		}
		a.writeDrainStop = nil
		if a.writeDrainPins > 0 {
			return
		}
		a.writeState.ExpireDrainAt(a.clock.Now())
		if !a.writeState.DrainUntil.IsZero() {
			a.scheduleWriteDrainLocked()
		}
	})
}

func (a *Application) scheduleReadDrainLocked() {
	a.readDrainGeneration++
	if a.readDrainStop != nil {
		a.readDrainStop()
		a.readDrainStop = nil
	}
	if a.terminal != nil || a.readState.DrainUntil.IsZero() {
		return
	}
	generation := a.readDrainGeneration
	delay := a.readState.DrainUntil.Sub(a.clock.Now())
	if delay <= 0 {
		delay = time.Nanosecond
	}
	a.readDrainStop = a.clock.AfterFunc(delay, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.terminal != nil || generation != a.readDrainGeneration {
			return
		}
		a.readDrainStop = nil
		if a.readDrainPins > 0 {
			return
		}
		a.expireReadDrainLocked(a.clock.Now())
		if !a.readState.DrainUntil.IsZero() {
			a.scheduleReadDrainLocked()
		}
	})
}

func (a *Application) pinWriteDrainLocked(now time.Time) {
	a.writeState.ExpireDrainAt(now)
	a.writeDrainPins++
}

func (a *Application) unpinWriteDrainLocked() {
	a.writeDrainPins--
	if a.writeDrainPins != 0 || a.terminal != nil {
		return
	}
	a.writeState.ExpireDrainAt(a.clock.Now())
	a.scheduleWriteDrainLocked()
}

func (a *Application) pinReadDrainLocked(now time.Time) {
	a.expireReadDrainLocked(now)
	a.readDrainPins++
}

func (a *Application) unpinReadDrainLocked() {
	a.readDrainPins--
	if a.readDrainPins != 0 || a.terminal != nil {
		return
	}
	a.expireReadDrainLocked(a.clock.Now())
	a.scheduleReadDrainLocked()
}

func (a *Application) expireReadDrainLocked(now time.Time) {
	phase, deadline, ok := a.readState.DrainInfo()
	a.readState.ExpireDrainAt(now)
	if ok && now.After(deadline) && a.readState.DrainUntil.IsZero() {
		a.receiver.ForgetPacketNumberSpace(a.routeInstanceID, a.hopLayer, a.readState.Direction, phase)
	}
}

func (a *Application) stopDrainTimersLocked() {
	a.writeDrainGeneration++
	a.readDrainGeneration++
	if a.writeDrainStop != nil {
		a.writeDrainStop()
		a.writeDrainStop = nil
	}
	if a.readDrainStop != nil {
		a.readDrainStop()
		a.readDrainStop = nil
	}
}
