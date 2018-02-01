/* Sendmail implementation using curl instead of writing it ourselves.
 * Useful for sending SMTP traffic over authenticated hosts.
 *
 */

#ifdef SENDMAIL_CURL
#include <curl/curl.h>
#include "maild.h"
#include "mail_list.h"

struct upload_status {
  int lines_read;
};

static char *payload_text[7] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;
 
  if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }
 
  data = payload_text[upload_ctx->lines_read];
 
  if(data) {
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    upload_ctx->lines_read++;
 
    return len;
  }
 
  return 0;
}

int OS_Sendsms(MailConfig *mail, struct tm *p, MailMsg *msg) {
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct curl_slist *recipients = NULL;
  struct upload_status upload_ctx;

  char hostname[1024];
  gethostname(hostname, 1024);

  char *messageId = NULL;
  int i = 0;

  for(i = 0; i<5; i++) {
    if(!payload_text[i]) {
      payload_text[i] = (char*)malloc(128);
    }
  }

  strftime(payload_text[0], 127, "Date: %a, %d %b %Y %T %z\r\n", p);
  sprintf(payload_text[1], "To: %s \r\n", mail->to[0]);
  sprintf(payload_text[2], "From: %s \r\n", mail->from);
  strftime(messageId, 127, "%a%d%b%Y%T%z", p);
  sprintf(payload_text[3], "Message-ID: <%s@%s> \r\n", messageId, hostname);
  sprintf(payload_text[4], "Subject: %s \r\n\r\n", msg->subject);

  payload_text[5] = msg->body;

  payload_text[6] = NULL;

  upload_ctx.lines_read = 0;
  curl = curl_easy_init();

  if(curl) {
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = 0;
    fprintf(stderr, "curl_easy_setopt() URL: %s\n", mail->smtpserver);
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/cacert.pem");
    curl_easy_setopt(curl, CURLOPT_URL, mail->smtpserver);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, "10.0.0.2,8.8.8.8,8.8.4.4");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if(mail->authsmtp) {
      curl_easy_setopt(curl, CURLOPT_USERNAME, mail->smtp_user);
      curl_easy_setopt(curl, CURLOPT_PASSWORD, mail->smtp_pass);
    }

    if(mail->securesmtp) {
      curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_TRY);
    }

    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, mail->from);
    recipients = curl_slist_append(recipients, mail->to[0]);

    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s (%s)\n", curl_easy_strerror(res), errbuf);
    }

    curl_slist_free_all(recipients);

    curl_easy_cleanup(curl);
  }

  return (int)res;
}

int OS_Sendmail(MailConfig *mail, struct tm *p) {
  MailNode *mailmsg;
  while((mailmsg = OS_PopLastMail()) != NULL) {
    OS_Sendsms(mail, p, mailmsg->mail);
    FreeMail(mailmsg);
  }

  return 0;
}

#endif
