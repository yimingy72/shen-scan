package agent

import (
	"bufio"
	"strconv"
	"strings"
)

func parseCPUTotals(line string) (total, idle uint64, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		values = append(values, value)
		total += value
	}
	idle = values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return total, idle, true
}

func parseMemoryKiB(contents string) (total, available uint64) {
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = value
		case "MemAvailable:":
			available = value
		case "VmRSS:":
			available = value
		}
	}
	return total, available
}

func kibToMiB(value uint64) float64 {
	return float64(value) / 1024
}
