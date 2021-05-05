package main

import (
	"bufio"
	"log"
	"os"
	"os/exec"
	"strings"
)

var proc *subprocess

type subprocess struct {
	cmd    *exec.Cmd
	stdin  *os.File
	stdout *bufio.Scanner
	debug  bool
}

func initSubprocess(bin string, broker string) {
	stdinChild, stdin, err := os.Pipe()
	if err != nil {
		log.Fatal("os.Pipe error", err)
	}

	stdout, stdoutChild, err := os.Pipe()
	if err != nil {
		log.Fatal("os.Pipe error", err)
	}

	cmd := exec.Command(bin, broker)
	cmd.Stdin = stdinChild
	cmd.Stdout = stdoutChild
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatal("Command.Start error", err)
	}

	log.Print("started client subprocess: ", bin)

	proc = &subprocess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewScanner(stdout),
	}
}

func (proc *subprocess) writeLine(cmd ...string) {
	line := strings.Join(cmd, "\t")
	if proc.debug {
		log.Print(">> " + line)
	}
	_, err := proc.stdin.WriteString(line + "\n")
	if err != nil {
		log.Fatal("subprocess stdin error", err)
	}
}

func (proc *subprocess) readLine() []string {
	if !proc.stdout.Scan() {
		log.Fatal("subprocess stdout error", proc.stdout.Err())
	}
	line := proc.stdout.Text()
	if proc.debug {
		log.Print("<< " + line)
	}
	return strings.Split(line, "\t")
}

func (proc *subprocess) expect(res, descr string) string {
	cmd := proc.readLine()
	if !assert(cmd[0] == res, descr) {
		log.Print(cmd)
		return ""
	}
	return cmd[1]
}

func (proc *subprocess) stop() {
	proc.stdin.Close()
	if err := proc.cmd.Wait(); err != nil {
		log.Fatal("Command.Wait error", err)
	}

	log.Print("subprocess clean exit")
}
