package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = map[string]Level{
	"debug":   LevelDebug,
	"info":    LevelInfo,
	"warn":    LevelWarn,
	"warning": LevelWarn,
	"error":   LevelError,
}

var levelStrings = map[Level]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
}

type Options struct {
	Level    Level
	Console  io.Writer
	FilePath string
}

type Logger struct {
	mu      sync.Mutex
	level   Level
	writer  io.Writer
	console io.Writer
	file    *os.File
}

func ParseLevel(value string) (Level, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return LevelInfo, nil
	}
	level, ok := levelNames[value]
	if !ok {
		return LevelInfo, fmt.Errorf("unknown log level %q", value)
	}
	return level, nil
}

func New(opts Options) (*Logger, error) {
	console := opts.Console
	if console == nil {
		console = os.Stderr
	}

	writers := []io.Writer{console}
	var logFile *os.File
	if strings.TrimSpace(opts.FilePath) != "" {
		filePath := strings.TrimSpace(opts.FilePath)
		dir := filepath.Dir(filePath)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, fmt.Errorf("creating log directory: %w", err)
			}
		}
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("opening log file: %w", err)
		}
		logFile = f
		writers = append(writers, f)
	}

	multi := io.MultiWriter(writers...)
	logger := &Logger{
		level:   opts.Level,
		writer:  multi,
		console: console,
		file:    logFile,
	}
	return logger, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

func (l *Logger) ConsoleWriter() io.Writer {
	return l.console
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

func (l *Logger) logf(level Level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level < l.level {
		return
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	levelName := levelStrings[level]
	if levelName == "" {
		levelName = "INFO"
	}
	message := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	line := fmt.Sprintf("%s [%s] %s", timestamp, levelName, message)
	_, _ = l.writer.Write([]byte(line))
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logf(LevelDebug, format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.logf(LevelInfo, format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.logf(LevelWarn, format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logf(LevelError, format, args...)
}

type writerAdapter struct {
	logger *Logger
	level  Level
}

func (w writerAdapter) Write(p []byte) (int, error) {
	if len(p) == 0 || w.logger == nil {
		return len(p), nil
	}
	text := string(p)
	text = strings.ReplaceAll(text, "\r", "")
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		w.logger.logf(w.level, "%s", trimmed)
	}
	return len(p), nil
}

func (l *Logger) Writer(level Level) io.Writer {
	return writerAdapter{logger: l, level: level}
}
