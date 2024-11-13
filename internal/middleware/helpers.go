/*
 * Copyright 2024 Jonas Kaninda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package middleware

import (
	"encoding/json"
	"fmt"
	errorinterceptor "github.com/jkaninda/goma-gateway/pkg/error-interceptor"
	"net/http"
)

func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
func allowedOrigin(origins []string, origin string) bool {
	for _, o := range origins {
		if o == origin {
			return true
		}
		continue
	}
	return false

}
func canInterceptError(code int, errors []errorinterceptor.Error) bool {
	for _, er := range errors {
		if er.Code == code {
			return true
		}
		continue

	}
	return false
}
func errMessage(code int, errors []errorinterceptor.Error) (string, error) {
	for _, er := range errors {
		if er.Code == code {
			if len(er.Message) != 0 {
				return er.Message, nil
			}
			continue
		}
	}
	return "", fmt.Errorf("%d errors occurred", code)
}

// RespondWithError is a helper function to handle error responses with flexible content type
func RespondWithError(w http.ResponseWriter, statusCode int, logMessage string, errorIntercept errorinterceptor.ErrorInterceptor) {
	message, err := errMessage(statusCode, errorIntercept.Errors)
	if err != nil {
		message = logMessage
	}
	if errorIntercept.ContentType == errorinterceptor.ApplicationJson {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		err := json.NewEncoder(w).Encode(ProxyResponseError{
			Success: false,
			Code:    statusCode,
			Message: message,
		})
		if err != nil {
			return
		}
		return
	} else {
		w.Header().Set("Content-Type", "plain/text;charset=utf-8")
		w.WriteHeader(statusCode)
		_, err2 := w.Write([]byte(message))
		if err2 != nil {
			return
		}
		return
	}
}
