package engine

import "context"

// Daemon is fail2ban as the API asks things of it: the real one, supervised, or the demo's.
type Daemon interface {
	State() DaemonState
	// Restart stops fail2ban and starts it again, or starts it now if it is waiting to.
	Restart()
	Jails(ctx context.Context) ([]Jail, error)
	// Banned is every banned address, by jail.
	Banned(ctx context.Context) (map[string][]string, error)
	Ban(ctx context.Context, jail, ip string) error
	// Unban lifts a ban in one jail, or in every jail when jail is "".
	Unban(ctx context.Context, jail, ip string) error
	// Actions is the actions each running jail has, by jail.
	Actions(ctx context.Context) (map[string][]string, error)
}

// Tools are fail2ban's own programs, run over a composed configuration directory.
type Tools interface {
	// Check is whether fail2ban would start with the configuration in dir.
	Check(ctx context.Context, dir string) Result
	// Reload hands the running fail2ban the configuration in dir.
	Reload(ctx context.Context, dir string) Result
	// Regex runs filter, a name with options or not, over the file at log.
	Regex(ctx context.Context, dir, log, filter string) Result
	// Actions is the actions the configuration in dir gives each jail it enables, by jail.
	Actions(ctx context.Context, dir string) (map[string][]string, error)
}

// Result is what one of the tools said.
type Result struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// DaemonState is how fail2ban is doing.
type DaemonState struct {
	// State is starting, running or stopped.
	State   string `json:"state"`
	Version string `json:"version"`
	Pid     int    `json:"pid"`
	// Since is when it entered this state, in Unix seconds.
	Since int64 `json:"since"`
	// Restarts counts the times it stopped without being asked to.
	Restarts int `json:"restarts"`
	// LastExit is how it last stopped, or "".
	LastExit string `json:"lastExit"`
}

const (
	Starting = "starting"
	Running  = "running"
	Stopped  = "stopped"
)

// Jail is one running jail and its counts.
type Jail struct {
	Name        string   `json:"name"`
	FailedNow   int64    `json:"failedNow"`
	FailedTotal int64    `json:"failedTotal"`
	BannedNow   int64    `json:"bannedNow"`
	BannedTotal int64    `json:"bannedTotal"`
	Logs        []string `json:"logs"`
	FindTime    int64    `json:"findTime"`
	BanTime     int64    `json:"banTime"`
	MaxRetry    int64    `json:"maxRetry"`
	// File is the edited file that defines it, and Filter the filter it names there, without
	// options: both filled in by the API, from what is edited.
	File   *FileRef `json:"file"`
	Filter string   `json:"filter"`
}

// FileRef names an edited file.
type FileRef struct {
	Kind Kind   `json:"kind"`
	Name string `json:"name"`
}
