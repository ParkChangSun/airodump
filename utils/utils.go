package utils

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"text/tabwriter"
	"time"
)

type DumpRow struct {
	BSSId   string
	Beacons int
	ESSId   string
	Power   int
	Channel int
	Cipher  string
}

var dumpMsgMap = make(map[string]DumpRow)
var bssAsKeyOrder = make([]string, 0)

var clear = "\x1b[2J"
var home = "\x1b[H"

var startTime = time.Now()

func PanicError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func BytesToMac(r []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", r[0], r[1], r[2], r[3], r[4], r[5])
}

func IwModChannel(iwInterface string, channelNum int) error {
	cmd := exec.Command("iwconfig", iwInterface, "channel", fmt.Sprint(channelNum))
	return cmd.Run()
}

func TimeTrack(start time.Time) string {
	elapsed := time.Since(start)
	return fmt.Sprintf("%dm %ds", int(elapsed.Minutes()), int(elapsed.Seconds()))
}

func PrintDump(dumpChan chan DumpRow) {
	for row := range dumpChan {
		val, ok := dumpMsgMap[row.BSSId]
		if ok {
			row.Beacons = val.Beacons
		} else {
			bssAsKeyOrder = append(bssAsKeyOrder, row.BSSId)
		}
		row.Beacons++
		dumpMsgMap[row.BSSId] = row

		writer := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Print(clear, home, "\n")
		fmt.Printf("[ Channel %2d ] [ Elapsed TIme %s ] [ AiroDump - BoB ]\n\n", row.Channel, TimeTrack(startTime))
		fmt.Fprint(writer, "BSSId\tBeacons\tChannel\tPower\tCipher\tESSId\t\n")
		fmt.Fprintf(writer, "\t\t\t\t\t\t\n")
		for _, bssKey := range bssAsKeyOrder {
			el := dumpMsgMap[bssKey]
			_, err := fmt.Fprintf(writer, "%s\t%d\t%d\t%d\t%s\t%s\t\n", el.BSSId, el.Beacons, el.Channel, el.Power, el.Cipher, el.ESSId)
			PanicError(err)
		}
		err := writer.Flush()
		PanicError(err)
	}
}
