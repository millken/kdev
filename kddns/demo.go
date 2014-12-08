package main
import (
	"github.com/d2g/netlink"
	"fmt"
	"time"
)
const (
	 NETLINK_CHANNEL int = 31
)

func work() {
	for {
		t := netlink.GetNetlinkSocket(NETLINK_CHANNEL, netlink.Unicast)
		err := t.Connect()
		defer t.Close()
		if err != nil {
			fmt.Println(err)
		}
		t.Write([]byte("test..\n"))
	}
	time.Sleep(time.Second * 1)
}

func main() {
	netConn := netlink.GetNetlinkSocket(NETLINK_CHANNEL, netlink.Unicast)
	go work()
	netConn.SetHandleFunc(func(message []byte) error{
		fmt.Println(string(message))
		return nil
	})
	netConn.ListenAndServe()
}

