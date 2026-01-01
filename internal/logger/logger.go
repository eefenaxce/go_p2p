package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

type Logger struct {
	mu          sync.Mutex
	level       LogLevel
	module      string
	file        *os.File
	fileWriter  io.Writer
	console     io.Writer
	maxSize     int64
	currentSize int64
	logPath     string
	logFile     string
}

var (
	globalLogger *Logger
	once         sync.Once
)

func NewLogger(module, logPath string, level LogLevel) *Logger {
	if err := os.MkdirAll(logPath, 0755); err != nil {
		fmt.Printf("创建日志目录失败: %v\n", err)
		return nil
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logFile := filepath.Join(logPath, fmt.Sprintf("%s_%s.log", module, timestamp))

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("打开日志文件失败: %v\n", err)
		return nil
	}

	logger := &Logger{
		level:       level,
		module:      module,
		file:        file,
		fileWriter:  file,
		console:     os.Stdout,
		maxSize:     100 * 1024 * 1024,
		logPath:     logPath,
		logFile:     logFile,
		currentSize: 0,
	}

	if info, err := file.Stat(); err == nil {
		logger.currentSize = info.Size()
	}

	return logger
}

func InitGlobalLogger(module, logPath string, level LogLevel) {
	once.Do(func() {
		globalLogger = NewLogger(module, logPath, level)
	})
}

func GetGlobalLogger() *Logger {
	return globalLogger
}

func (l *Logger) formatMessage(level LogLevel, format string, args ...interface{}) string {
	levelStr := ""
	switch level {
	case DEBUG:
		levelStr = "DEBUG"
	case INFO:
		levelStr = "INFO "
	case WARN:
		levelStr = "WARN "
	case ERROR:
		levelStr = "ERROR"
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	message := fmt.Sprintf(format, args...)

	return fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, levelStr, l.module, message)
}

func (l *Logger) write(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	message := l.formatMessage(level, format, args...)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.console != nil {
		fmt.Fprintln(l.console, message)
	}

	if l.fileWriter != nil {
		fmt.Fprintln(l.fileWriter, message)
		l.currentSize += int64(len(message)) + 1

		if l.currentSize >= l.maxSize {
			l.rotateLog()
		}
	}
}

func (l *Logger) rotateLog() {
	if l.file != nil {
		l.file.Close()
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	newLogFile := filepath.Join(l.logPath, fmt.Sprintf("%s_%s.log", l.module, timestamp))

	file, err := os.OpenFile(newLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("创建新日志文件失败: %v\n", err)
		return
	}

	l.file = file
	l.fileWriter = file
	l.currentSize = 0
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.write(DEBUG, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.write(INFO, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.write(WARN, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.write(ERROR, format, args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	pc, _, _, _ := runtime.Caller(1)
	caller := runtime.FuncForPC(pc)
	callerName := "unknown"
	if caller != nil {
		callerName = caller.Name()
	}
	l.write(DEBUG, fmt.Sprintf("[%s] %s", callerName, format), args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	pc, _, _, _ := runtime.Caller(1)
	caller := runtime.FuncForPC(pc)
	callerName := "unknown"
	if caller != nil {
		callerName = caller.Name()
	}
	l.write(INFO, fmt.Sprintf("[%s] %s", callerName, format), args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	pc, _, _, _ := runtime.Caller(1)
	caller := runtime.FuncForPC(pc)
	callerName := "unknown"
	if caller != nil {
		callerName = caller.Name()
	}
	l.write(WARN, fmt.Sprintf("[%s] %s", callerName, format), args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	pc, _, _, _ := runtime.Caller(1)
	caller := runtime.FuncForPC(pc)
	callerName := "unknown"
	if caller != nil {
		callerName = caller.Name()
	}
	l.write(ERROR, fmt.Sprintf("[%s] %s", callerName, format), args...)
}

func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) SetConsoleOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.console = w
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Close()
		l.file = nil
		l.fileWriter = nil
	}
}

func Debug(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debug(format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Info(format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warn(format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Error(format, args...)
	}
}

func Debugf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debugf(format, args...)
	}
}

func Infof(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Infof(format, args...)
	}
}

func Warnf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warnf(format, args...)
	}
}

func Errorf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Errorf(format, args...)
	}
}
