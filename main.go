package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func smtpCheck(mxHost, mailFrom, rcptTo string) (map[string]string, error) {
	logs := make(map[string]string)

	// 1. Connect to MX host
	conn, err := net.Dial("tcp", mxHost+":25")
	if err != nil {
		logs["connection"] = fmt.Sprintf("connection error: %v", err)
		return logs, err
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	activeConn := conn
	logs["connection"] = "connected successfully"

	// 2. Read server banner
	banner, _ := reader.ReadString('\n')
	logs["banner"] = strings.TrimSpace(banner)

	// Helper: send EHLO
	sendEHLO := func(c net.Conn) (bool, error) {
		_, err := fmt.Fprintf(c, "EHLO tm71.top\r\n")  // this should be your domain mail server
		if err != nil {
			return false, err
		}
		hasStartTLS := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			if strings.Contains(strings.ToUpper(line), "STARTTLS") {
				hasStartTLS = true
			}
			if len(line) < 4 || line[3] != '-' {
				break
			}
		}
		return hasStartTLS, nil
	}

	// 3. EHLO first time
	hasStartTLS, err := sendEHLO(activeConn)
	if err != nil {
		logs["ehlo"] = fmt.Sprintf("EHLO error: %v", err)
		return logs, err
	}
	if hasStartTLS {
		logs["ehlo_caps"] = "STARTTLS supported"
	} else {
		logs["ehlo_caps"] = "STARTTLS NOT supported"
	}

	// 4. Try STARTTLS if supported
	if hasStartTLS {
		fmt.Fprintf(activeConn, "STARTTLS\r\n")
		starttlsResp, _ := reader.ReadString('\n')
		if !strings.HasPrefix(starttlsResp, "220") {
			logs["starttls"] = fmt.Sprintf("STARTTLS failed: %s", strings.TrimSpace(starttlsResp))
		} else {
			tlsConn := tls.Client(activeConn, &tls.Config{
				ServerName:         mxHost,
				InsecureSkipVerify: true,
			})
			if err := tlsConn.Handshake(); err != nil {
				logs["tls_handshake"] = fmt.Sprintf("TLS handshake error: %v", err)
				logs["tls_fallback"] = "Continuing with plain connection"
				// fallback: continue with plain connection
			} else {
				activeConn = tlsConn
				reader = bufio.NewReader(activeConn)
				logs["tls_handshake"] = "TLS handshake successful"
				// EHLO again after TLS
				if _, err := sendEHLO(activeConn); err == nil {
					logs["ehlo_tls"] = "EHLO after TLS successful"
				}
			}
		}
	}

	// 5. MAIL FROM
	fmt.Fprintf(activeConn, "MAIL FROM:<%s>\r\n", mailFrom)
	mailResp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(mailResp, "250") {
		logs["mail_from"] = fmt.Sprintf("MAIL FROM rejected: %s", strings.TrimSpace(mailResp))
		return logs, fmt.Errorf("MAIL FROM rejected")
	}
	logs["mail_from"] = "MAIL FROM accepted"

	// 6. RCPT TO
	fmt.Fprintf(activeConn, "RCPT TO:<%s>\r\n", rcptTo)
	rcptResp, _ := reader.ReadString('\n')
	logs["rcpt_to"] = strings.TrimSpace(rcptResp)

	// 7. QUIT
	fmt.Fprintf(activeConn, "QUIT\r\n")

	return logs, nil
}

func smtpStatus(code int) string {
	switch code {
	case 101:
		return "Server connection error (wrong server name or connection port)"
	case 211:
		return "System status (response to HELP)"
	case 214:
		return "Help message (response to HELP)"
	case 220:
		return "The server is ready (response to connection attempt)"
	case 221:
		return "The server closes the transmission channel"
	case 235:
		return "Authentication successful (response to AUTH)"
	case 250:
		return "Deliverable"
	case 251:
		return "User not local, but server will forward message"
	case 252:
		return "Server cannot verify user (message accepted for delivery)"
	case 334:
		return "Response to AUTH (security mechanism accepted)"
	case 354:
		return "Start mail input; end with <CRLF>.<CRLF>"
	case 421:
		return "Service not available, closing transmission channel"
	case 422:
		return "Recipient’s mailbox exceeded storage limit"
	case 431:
		return "File overload (too many messages to a domain)"
	case 441:
		return "No response from recipient’s server"
	case 442:
		return "Connection dropped"
	case 446:
		return "Internal loop detected"
	case 450:
		return "Mailbox unavailable (busy or temporarily blocked)"
	case 451:
		return "Requested action aborted due to local error"
	case 452:
		return "Requested action not taken (insufficient system storage)"
	case 454:
		return "TLS not available due to temporary reason"
	case 455:
		return "Server cannot accommodate parameters"
	case 471:
		return "Local spam filter error"
	case 500:
		return "Syntax error, command unrecognized"
	case 501:
		return "Syntax error in parameters or arguments"
	case 502:
		return "Command not implemented"
	case 503:
		return "Bad sequence of commands"
	case 504:
		return "Command parameter not implemented"
	case 510:
		return "Invalid email address"
	case 512:
		return "DNS error (check recipient address)"
	case 523:
		return "Total size of mailing exceeds recipient server limits"
	case 530:
		return "Authentication required (try STARTTLS)"
	case 535:
		return "Authentication failed"
	case 538:
		return "Encryption required for authentication mechanism"
	case 541:
		return "Message rejected by spam filter"
	case 550:
		return "Mailbox unavailable / not found / relay denied"
	case 551:
		return "User not local (forward path will be specified)"
	case 552:
		return "Mailbox full (action aborted)"
	case 553:
		return "Invalid or malformed email address"
	case 554:
		return "Transaction failed due to unknown error"
	case 555:
		return "MAIL FROM/RCPT TO parameters not recognized"
	default:
		return "Unknown or unsupported SMTP status code"
	}
}

func main() {
	app := gin.Default()
	app.Use(gin.Recovery(), gin.Logger())

	app.POST("/email-check", func(c *gin.Context) {
		var body map[string]interface{}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		email, ok := body["email"].(string)
		if !ok || !strings.Contains(email, "@") {
			c.JSON(400, gin.H{"error": "Invalid email", "errorStatus": true})
			return
		}

		domain := strings.Split(email, "@")[1]
		mxRecords, err := net.LookupMX(domain)
		if err != nil || len(mxRecords) == 0 {
			c.JSON(400, gin.H{"error": "No MX records found", "errorStatus": true})
			return
		}

		mxHost := strings.TrimSuffix(mxRecords[0].Host, ".")

		// Replace with your sender email
		mailFrom := "rmtomal@tm71.top"  // this should be your domain mail server email

		logs, err := smtpCheck(mxHost, mailFrom, email)
		if err != nil {
			c.JSON(400, gin.H{
				"status":      err.Error(),
				"logs":        logs,
				"errorStatus": true,
			})
			return
		}

		cut := logs["rcpt_to"][:3]
		fmt.Println(cut)
		var status string
		if len(cut) < 1 {
			status = "Not readable status."
		}
		code, errData := strconv.Atoi(cut)
		if errData != nil {
			status = "Not readable status."
		}
		status = smtpStatus(code)
		isOk := false
		if code == 250 {
			isOk = true
		}
		c.JSON(200, gin.H{
			"status":        status,
			"mx_host":       mxHost,
			"logs":          logs,
			"isDeliverable": isOk,
			"errorStatus":   false,
		})
	})

	app.Run(":8080")
}
