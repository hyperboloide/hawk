package hawk_test

import (
	"github.com/gin-gonic/gin"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestHawk(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Hawk Suite")
}

var _ = BeforeSuite(func() {
	gin.SetMode(gin.ReleaseMode)
})
