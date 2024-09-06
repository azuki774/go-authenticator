package util

import (
	"fmt"
	"math/rand/v2"
	"time"
)

var NowFunc = time.Now

func PublishID() string {
	return fmt.Sprintf("%x", rand.Uint64())
}
