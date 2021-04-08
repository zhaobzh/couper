//go:generate go run assets/generate/generate.go

package main

import (
	"context"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/avenga/couper/command"
	"github.com/avenga/couper/config"
	"github.com/avenga/couper/config/configload"
	"github.com/avenga/couper/config/env"
	"github.com/avenga/couper/config/runtime"
	"github.com/avenga/couper/logging"
)

var (
	fields = logrus.Fields{
		"build":   runtime.BuildName,
		"version": runtime.VersionName,
	}
	hook logrus.Hook
)

func main() {
	logrus.Exit(realmain(os.Args))
}

func realmain(arguments []string) int {
	args := command.NewArgs(arguments)
	ctx := context.Background()

	if len(args) == 0 || command.NewCommand(ctx, args[0]) == nil {
		command.Help()
		return 1
	}

	cmd := args[0]
	args = args[1:]

	if cmd == "version" { // global options are not required, fast exit.
		_ = command.NewCommand(ctx, cmd).Execute(args, nil, nil)
		return 0
	}

	type globalFlags struct {
		FilePath  string `env:"file"`
		FileWatch bool   `env:"watch"`
		LogFormat string `env:"log_format"`
		LogPretty bool `env:"log_pretty"`
	}
	var flags globalFlags

	set := flag.NewFlagSet("global", flag.ContinueOnError)
	set.StringVar(&flags.FilePath, "f", config.DefaultFilename, "-f ./couper.hcl")
	set.BoolVar(&flags.FileWatch, "watch", false, "-watch")
	set.StringVar(&flags.LogFormat, "log-format", config.DefaultSettings.LogFormat, "-log-format=common")
	set.BoolVar(&flags.LogPretty, "log-pretty", config.DefaultSettings.LogPretty, "-log-pretty")
	err := set.Parse(args.Filter(set))
	if err != nil {
		newLogger(flags.LogFormat, flags.LogPretty).Error(err)
		return 1
	}

	env.Decode(&flags)

	confFile, err := configload.LoadFile(flags.FilePath)
	if err != nil {
		newLogger(flags.LogFormat, flags.LogPretty).Error(err)
		return 1
	}

	// The file gets initialized with the default settings, flag args are preferred over file settings.
	// Only override file settings if the flag value differ from the default.
	if flags.LogFormat != config.DefaultSettings.LogFormat {
		confFile.Settings.LogFormat = flags.LogFormat
	}
	if flags.LogPretty != config.DefaultSettings.LogPretty {
		confFile.Settings.LogPretty = flags.LogPretty
	}
	logger := newLogger(confFile.Settings.LogFormat, confFile.Settings.LogPretty)

	wd, err := os.Getwd()
	if err != nil {
		logger.Error(err)
		return 1
	}
	logger.Infof("working directory: %s", wd)

	if !flags.FileWatch {
		if err = command.NewCommand(ctx, cmd).Execute(args, confFile, logger); err != nil {
			logger.Error(err)
			return 1
		}
		return 0
	}

	logger.WithFields(fields).Info("watching configuration file")
	errCh := make(chan error, 1)

	execCmd, restartSignal := newRestartableCommand(ctx, cmd)
	go func() {
		errCh <- execCmd.Execute(args, confFile, logger)
	}()

	reloadCh := watchConfigFile(confFile.Filename, logger)
	for {
		select {
		case err = <-errCh:
			if err != nil {
				if netErr, ok := err.(*net.OpError); ok {
					if netErr.Op == "listen" {
						logger.Errorf("retry due to listen error: %v", netErr)
						// configuration load succeeded at this point, just restart the command
						execCmd, restartSignal = newRestartableCommand(ctx, cmd) // replace previous pair
						time.Sleep(time.Millisecond * 100)
						go func() {
							errCh <- execCmd.Execute(args, confFile, logger)
						}()
						continue
					}
				}
				logger.Error(err)
				return 1
			}
			return 0
		case <-reloadCh:
			logger.WithFields(fields).Info("reloading couper configuration")
			cf, reloadErr := configload.LoadFile(confFile.Filename) // we are at wd, just filename
			if reloadErr != nil {
				logger.WithFields(fields).Errorf("reload failed: %v", reloadErr)
				continue
			}
			// dry run configuration
			_, reloadErr = runtime.NewServerConfiguration(cf, logger.WithFields(fields), nil)
			if reloadErr != nil {
				logger.WithFields(fields).Errorf("reload failed: %v", reloadErr)
				continue
			}

			confFile = cf
			restartSignal <- struct{}{}                              // (hard) shutdown running couper
			<-errCh                                                  // drain current error due to cancel and ensure closed ports
			execCmd, restartSignal = newRestartableCommand(ctx, cmd) // replace previous pair
			go func() {
				// logger settings update gets ignored at this point
				// have to be locked for an update, skip this feature for now
				errCh <- execCmd.Execute(args, confFile, logger)
			}()
		}
	}
}

// newLogger creates a log instance with the configured formatter.
// Since the format option may required to be correct in early states
// we parse the env configuration on every call.
func newLogger(format string, pretty bool) *logrus.Entry {
	logger := logrus.New()
	logger.Out = os.Stdout
	if hook != nil {
		logger.AddHook(hook)
		logger.Out = ioutil.Discard
	}

	settings := &config.Settings{
		LogFormat: format,
		LogPretty: pretty,
	}
	env.Decode(settings)

	logConf := &logging.Config{
		TypeFieldKey: "couper_daemon",
	}
	env.Decode(logConf)

	if settings.LogFormat == "json" {
		logger.SetFormatter(logging.NewJSONColorFormatter(logConf.ParentFieldKey, settings.LogPretty))
	}
	logger.Level = logrus.DebugLevel
	return logger.WithField("type", logConf.TypeFieldKey).WithFields(fields)
}

func watchConfigFile(name string, logger logrus.FieldLogger) <-chan struct{} {
	reloadCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second / 4)
		defer ticker.Stop()
		var lastChange time.Time
		for {
			<-ticker.C
			fileInfo, fileErr := os.Stat(name)
			if fileErr != nil {
				logger.WithFields(fields).Error(fileErr)
				continue
			}

			if lastChange.IsZero() { // first round
				lastChange = fileInfo.ModTime()
				continue
			}

			if fileInfo.ModTime().After(lastChange) {
				reloadCh <- struct{}{}
			}
			lastChange = fileInfo.ModTime()
		}
	}()
	return reloadCh
}

func newRestartableCommand(ctx context.Context, cmd string) (command.Cmd, chan<- struct{}) {
	signal := make(chan struct{})
	watchContext, cancelFn := context.WithCancel(ctx)
	go func() {
		<-signal
		cancelFn()
	}()
	return command.NewCommand(watchContext, cmd), signal
}
