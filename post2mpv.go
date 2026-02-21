package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"github.com/google/uuid"
)

const (
	DEFAULT_HOST   = "127.0.0.1"
	DEFAULT_PORT   = 7531
	TOKEN_HEADER   = "X-POST2MPV-TOKEN"
	SHUTDOWN_TIMEOUT = 10 * time.Second
	VERSION = "1.0.0"
)

var (
	host       = flag.String("host", DEFAULT_HOST, "host to bind")
	port       = flag.Int("port", DEFAULT_PORT, "port to bind")
	token      = flag.String("token", "", "shared token for authorization")
	configFile = flag.String("config", "", "configuration file path")
	public     = flag.Bool("public", false, "bind to 0.0.0.0 (dangerous without token)")
)

// logWriter форматирует дату как dd.mm.yyyy hh:mm:ss
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	now := time.Now()
	prefix := fmt.Sprintf("%02d.%02d.%04d %02d:%02d:%02d ",
		now.Day(), now.Month(), now.Year(),
		now.Hour(), now.Minute(), now.Second())
	return os.Stderr.Write(append([]byte(prefix), p...))
}

// ProcessManager отслеживает активные процессы
type ProcessManager struct {
	mu    sync.RWMutex
	procs map[string]*ProcessInfo
}

type ProcessInfo struct {
	ID      string
	Cmd     *exec.Cmd
	Started time.Time
}

type RequestPayload struct {
	URL    string   `json:"url"`
	Action string   `json:"action"`
	Params []string `json:"params"`
	Args   []string `json:"args"`
	Output string   `json:"output"`
}

type ResponsePayload struct {
	Status string `json:"status"`
	JobID  string `json:"job_id,omitempty"`
	Detail string `json:"detail,omitempty"`
	Action string `json:"action,omitempty"`
}

var pm = &ProcessManager{
	procs: make(map[string]*ProcessInfo),
}

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), `Usage: post2mpv [OPTION]...

	HTTP server for mpv/peerflix/yt-dlp control

	Options:
	`)
	flag.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), `
	Examples:
	post2mpv --host 127.0.0.1 --port 7531 --token mysecret
	POST2MPV_TOKEN=mysecret post2mpv
	post2mpv --public --token mysecret
	post2mpv --config /etc/post2mpv/post2mpv.conf

	Configuration file format (KEY=VALUE):
	POST2MPV_TOKEN=your_token
	POST2MPV_HOST=127.0.0.1
	POST2MPV_PORT=7531

	Default config locations:
	/etc/post2mpv/post2mpv.conf
	$HOME/.config/post2mpv/post2mpv.conf

	API:
	POST / with JSON body:
	{
	"url": "https://example.com/video.mp4",
	"action": "play|download|translate",
	"params": ["--option"],
	"output": "/path/to/file"
}

Authentication:
Send header: X-POST2MPV-TOKEN: <token>

For more information, visit:
https://github.com/netnomadd/post2mpv
`)
}

func main() {
	log.SetFlags(0)
	log.SetOutput(logWriter{})

	flag.Usage = printUsage
	flag.Parse()

	// Проверка аргументов
	args := flag.Args()
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" {
			printUsage()
			os.Exit(0)
		}
		if arg == "-v" || arg == "--version" || arg == "version" {
			fmt.Printf("post2mpv %s\n", VERSION)
			os.Exit(0)
		}
	}

	// Чтение конфигурации
	config := loadConfig(*configFile)

	// Приоритет: флаг > конфиг > env переменная > значение по умолчанию
	effectiveToken := *token
	if effectiveToken == "" {
		effectiveToken = config["POST2MPV_TOKEN"]
	}
	if effectiveToken == "" {
		effectiveToken = os.Getenv("POST2MPV_TOKEN")
	}

	effectiveHost := *host
	if effectiveHost == DEFAULT_HOST && config["POST2MPV_HOST"] != "" {
		effectiveHost = config["POST2MPV_HOST"]
	}

	effectivePort := *port
	if effectivePort == DEFAULT_PORT && config["POST2MPV_PORT"] != "" {
		if _, err := fmt.Sscanf(config["POST2MPV_PORT"], "%d", &effectivePort); err != nil {
			log.Printf("Warning: invalid port in config: %v", err)
		}
	}

	bindHost := effectiveHost
	if *public {
		bindHost = "0.0.0.0"
	}

	if bindHost != "127.0.0.1" && effectiveToken == "" {
		log.Println("WARNING: Binding to external interface without token is unsafe. Use --token or set POST2MPV_TOKEN.")
	}

	addr := fmt.Sprintf("%s:%d", bindHost, effectivePort)
	log.Printf("post2mpv %s listening on %s (token %s)", VERSION, addr, map[bool]string{true: "set", false: "not set"}[effectiveToken != ""])

	// Обработчики сигналов
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// HTTP сервер
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRequest(effectiveToken))

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Запуск сервера в отдельной горутине
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	// Ожидание сигнала завершения
	select {
		case sig := <-sigChan:
			log.Printf("Signal %v received, shutting down...", sig)
		case err := <-serverErrors:
			if err != http.ErrServerClosed {
				log.Printf("Server error: %v", err)
			}
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), SHUTDOWN_TIMEOUT)
	defer cancel()

	log.Println("Server stopping, terminating children...")
	terminateAllProcesses()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

// loadConfig читает конфигурационный файл (KEY=VALUE формат)
func loadConfig(configPath string) map[string]string {
	config := make(map[string]string)

	if configPath == "" {
		// Пробуем найти конфиг в стандартных местах
		candidates := []string{
			"/etc/post2mpv/post2mpv.conf",
			os.ExpandEnv("$HOME/.config/post2mpv/post2mpv.conf"),
		}

		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				configPath = path
				break
			}
		}
	}

	if configPath == "" {
		return config
	}

	file, err := os.Open(configPath)
	if err != nil {
		log.Printf("Warning: could not open config file %s: %v", configPath, err)
		return config
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Удаляем кавычки если есть
			value = strings.Trim(value, "\"'")
			config[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Warning: error reading config file: %v", err)
	}

	log.Printf("Loaded config from %s", configPath)
	return config
}

func handleRequest(expectedToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", fmt.Sprintf("Content-Type, %s", TOKEN_HEADER))

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(ResponsePayload{
				Status: "error",
				Detail: "only POST is allowed",
			})
			return
		}

		// Проверка токена
		if expectedToken != "" {
			if r.Header.Get(TOKEN_HEADER) != expectedToken {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(ResponsePayload{
					Status: "error",
					Detail: "invalid token",
				})
				log.Printf("Rejected request due to invalid token from %s", r.RemoteAddr)
				return
			}
		}

		// Чтение тела запроса
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ResponsePayload{
				Status: "error",
				Detail: "failed to read body",
			})
			return
		}
		defer r.Body.Close()

		if len(body) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ResponsePayload{
				Status: "error",
				Detail: "empty body",
			})
			return
		}

		// Парсинг JSON
		var payload RequestPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ResponsePayload{
				Status: "error",
				Detail: fmt.Sprintf("invalid json: %v", err),
			})
			return
		}

		if payload.URL == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ResponsePayload{
				Status: "error",
				Detail: "url required",
			})
			return
		}

		if payload.Action == "" {
			payload.Action = "play"
		}

		// Объединяем params и args
		params := payload.Params
		if len(params) == 0 && len(payload.Args) > 0 {
			params = payload.Args
		}

		log.Printf("Received action=%s url=%s from %s", payload.Action, payload.URL, r.RemoteAddr)

		var jobID string
		var respStatus int

		switch payload.Action {
			case "play":
				jobID = handlePlay(payload.URL, params)
				respStatus = http.StatusOK
			case "download":
				jobID = handleDownload(payload.URL, params, payload.Output)
				respStatus = http.StatusOK
			case "translate":
				jobID = handleTranslate(payload.URL, params)
				respStatus = http.StatusOK
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(ResponsePayload{
					Status: "error",
					Detail: fmt.Sprintf("unknown action: %s", payload.Action),
				})
				return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(respStatus)
		json.NewEncoder(w).Encode(ResponsePayload{
			Status: "ok",
			JobID:  jobID,
			Action: payload.Action,
		})
	}
}

func handlePlay(url string, params []string) string {
	var cmd *exec.Cmd

	if strings.HasPrefix(url, "magnet:") || strings.HasSuffix(url, ".torrent") {
		// peerflix для торрентов
		args := append([]string{url, "--"}, params...)
		cmd = exec.Command("peerflix", args...)
	} else {
		// mpv для прямых ссылок
		args := append([]string{"--no-terminal"}, params...)
		args = append(args, "--", url)
		cmd = exec.Command("mpv", args...)
	}

	return spawnAndTrack(cmd)
}

func handleDownload(url string, params []string, output string) string {
	args := []string{url, "-i"}
	if output != "" {
		args = append(args, "-o", output)
	}
	args = append(args, params...)

	cmd := exec.Command("yt-dlp", args...)
	return spawnAndTrack(cmd)
}

func handleTranslate(url string, params []string) string {
	args := append([]string{"--url", url}, params...)
	cmd := exec.Command("vot", args...)
	return spawnAndTrack(cmd)
}

// pipeToLog читает строки из r и пишет их в лог с префиксом job_id и потоком (stdout/stderr)
func pipeToLog(r io.Reader, jobID, stream string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		log.Printf("[%s] %s: %s", jobID, stream, scanner.Text())
	}
}

func spawnAndTrack(cmd *exec.Cmd) string {
	jobID := uuid.New().String()

	cmd.SysProcAttr = &syscall.SysProcAttr{}

	// На Unix: создаём новую сессию для контроля группы процессов
	if os.Getenv("GOOS") != "windows" {
		cmd.SysProcAttr.Setsid = true
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create stdout pipe: %v", err)
		return ""
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("Failed to create stderr pipe: %v", err)
		return ""
	}

	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start process: %v", err)
		return ""
	}

	procInfo := &ProcessInfo{
		ID:      jobID,
		Cmd:     cmd,
		Started: time.Now(),
	}

	pm.mu.Lock()
	pm.procs[jobID] = procInfo
	pm.mu.Unlock()

	log.Printf("Started process pid=%d job_id=%s", cmd.Process.Pid, jobID)

	go pipeToLog(stdoutPipe, jobID, "stdout")
	go pipeToLog(stderrPipe, jobID, "stderr")

	// Отслеживание завершения процесса в отдельной горутине
	go func() {
		err := cmd.Wait()
		exitCode := -1
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
					exitCode = status.ExitStatus()
				}
			}
		} else {
			exitCode = 0
		}

		pm.mu.Lock()
		delete(pm.procs, jobID)
		pm.mu.Unlock()

		log.Printf("Process finished pid=%d job_id=%s exit_code=%d", cmd.Process.Pid, jobID, exitCode)
	}()

	return jobID
}

func terminateAllProcesses() {
	pm.mu.Lock()
	procs := make([]*ProcessInfo, 0, len(pm.procs))
	for _, p := range pm.procs {
		procs = append(procs, p)
	}
	pm.mu.Unlock()

	if len(procs) == 0 {
		return
	}

	log.Printf("Terminating %d active child processes...", len(procs))

	// Фаза 1: мягкое завершение (SIGTERM)
	for _, procInfo := range procs {
		if procInfo.Cmd.Process != nil {
			if os.Getenv("GOOS") == "windows" {
				procInfo.Cmd.Process.Kill()
			} else {
				// Отправляем SIGTERM группе процессов
				syscall.Kill(-procInfo.Cmd.Process.Pid, syscall.SIGTERM)
			}
		}
	}

	// Ожидание завершения с таймаутом
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pm.mu.RLock()
		if len(pm.procs) == 0 {
			pm.mu.RUnlock()
			return
		}
		pm.mu.RUnlock()
		time.Sleep(100 * time.Millisecond)
	}

	// Фаза 2: принудительное завершение (SIGKILL)
	pm.mu.Lock()
	for _, procInfo := range pm.procs {
		if procInfo.Cmd.Process != nil {
			if os.Getenv("GOOS") == "windows" {
				procInfo.Cmd.Process.Kill()
			} else {
				syscall.Kill(-procInfo.Cmd.Process.Pid, syscall.SIGKILL)
			}
			log.Printf("Killed process pid=%d job_id=%s", procInfo.Cmd.Process.Pid, procInfo.ID)
		}
	}
	pm.procs = make(map[string]*ProcessInfo)
	pm.mu.Unlock()
}
