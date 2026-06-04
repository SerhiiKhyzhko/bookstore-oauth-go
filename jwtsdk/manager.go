package jwtsdk

import "github.com/SerhiiKhyzhko/bookstore_utils-go/logger"

func NewJwtManager(key string, logger *logger.Logger) *JwtManager {
	return &JwtManager{
		secretKey: key,
		logger:    logger,
	}
}
