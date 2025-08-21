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

type smtpResult struct {
	logs  map[string]string
	err   error
	email string
}

// Detect local hostname for EHLO
func getMyHostname() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.String()
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	return strings.TrimSuffix(names[0], ".")
}

// Perform basic SMTP check
func smtpCheck(mxHost, mailFrom, rcptTo string) smtpResult {
	logs := make(map[string]string)
	hostName := getMyHostname()

	println(hostName)

	conn, err := net.Dial("tcp", mxHost+":25")
	if err != nil {
		logs["connection"] = fmt.Sprintf("connection error: %v", err)
		return smtpResult{logs, err, rcptTo}
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	logs["connection"] = "connected"

	// Read server banner
	banner, _ := reader.ReadString('\n')
	logs["banner"] = strings.TrimSpace(banner)

	sendEHLO := func(c net.Conn) (bool, error) {
		_, err := fmt.Fprintf(c, "EHLO %s\r\n", hostName)
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

	// EHLO first
	hasStartTLS, _ := sendEHLO(conn)
	if hasStartTLS {
		logs["ehlo_caps"] = "STARTTLS supported"
		fmt.Fprintf(conn, "STARTTLS\r\n")
		resp, _ := reader.ReadString('\n')
		if strings.HasPrefix(resp, "220") {
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         mxHost,
				InsecureSkipVerify: true,
			})
			if err := tlsConn.Handshake(); err == nil {
				conn = tlsConn
				reader = bufio.NewReader(conn)
				logs["tls"] = "TLS handshake successful"
				sendEHLO(conn) // EHLO after TLS
			} else {
				logs["tls"] = fmt.Sprintf("TLS handshake failed: %v", err)
			}
		}
	}

	// MAIL FROM
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", mailFrom)
	mailResp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(mailResp, "250") {
		logs["mail_from"] = fmt.Sprintf("MAIL FROM rejected: %s", strings.TrimSpace(mailResp))
		return smtpResult{logs, fmt.Errorf("MAIL FROM rejected"), rcptTo}
	}
	logs["mail_from"] = "MAIL FROM accepted"

	// RCPT TO
	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", rcptTo)
	var rcptResp string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		rcptResp += line
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	logs["rcpt_to"] = strings.TrimSpace(rcptResp)

	fmt.Fprintf(conn, "QUIT\r\n")

	return smtpResult{logs, nil, rcptTo}
}

func smtpStatus(code int) string {
	switch code {
	case 250:
		return "Deliverable"
	case 550:
		return "Mailbox unavailable / not found / relay denied"
	default:
		return "Other SMTP response"
	}
}

func main() {
	app := gin.Default()
	app.POST("/email-check", func(c *gin.Context) {
		var body map[string]interface{}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		email, ok := body["email"].(string)
		if !ok || !strings.Contains(email, "@") {
			c.JSON(400, gin.H{"error": "Invalid email"})
			return
		}

		email = strings.ToLower(strings.TrimSpace(email))
		parts := strings.Split(email, "@")
		domain := parts[1]
		mxRecords, err := net.LookupMX(domain)
		if err != nil || len(mxRecords) == 0 {
			c.JSON(400, gin.H{"error": "No MX records found"})
			return
		}

		mxHost := strings.TrimSuffix(mxRecords[0].Host, ".")
		mailFrom := "rmtomal@tm71.top"

		results := make(chan smtpResult, 2)

		// Real email
		go func() {
			results <- smtpCheck(mxHost, mailFrom, email)
		}()

		// Fake email to detect catch-all
		fakeEmail := fmt.Sprintf("nonexistent_%d@%s", 12345, domain)
		go func() {
			results <- smtpCheck(mxHost, mailFrom, fakeEmail)
		}()

		res1 := <-results
		res2 := <-results

		var data smtpResult
		if res1.email != email {
			data = res1
			res1 = res2
			res2 = data
		}

		// Determine deliverability
		codeParts := res1.logs["rcpt_to"]
		code := 0
		if len(codeParts) > 0 {
			code, _ = strconv.Atoi(codeParts[:3])
		}
		isDeliverable := code == 250
		risky := isDeliverable && strings.Contains(res2.logs["rcpt_to"], "250") // catch-all detected

		c.JSON(200, gin.H{
			"status":        smtpStatus(code),
			"mx_host":       mxHost,
			"logs":          res1.logs,
			"isDeliverable": isDeliverable,
			"risky":         risky,
		})
	})

	app.Run(":8080")
}
