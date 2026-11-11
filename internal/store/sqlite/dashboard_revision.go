package sqlite

// DashboardRevision returns a cheap in-process generation counter for tenant
// dashboard data. Live pollers can skip full reloads while it is unchanged.
func (s *Store) DashboardRevision() uint64 {
	return s.dashboardRevision.Load()
}

func (s *Store) bumpDashboardRevision() {
	s.dashboardRevision.Add(1)
}
