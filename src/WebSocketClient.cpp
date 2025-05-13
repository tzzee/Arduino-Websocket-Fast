//#define DEBUGGING

#include "global.h"
#include "WebSocketClient.h"

#include "WebSocketClientSha1.h"
#include "WebSocketClientBase64.h"


bool WebSocketClient::handshake(Client &client, bool socketio, std::uint32_t timeoutMsec) {

    socket_client = &client;
    issocketio = socketio;
    strcpy(sid, "");

    // If there is a connected client->
    if (socket_client->connected()) {
        // Check request and look for websocket handshake
#ifdef DEBUGGING
            Serial.println(F("Client connected"));
#endif
        if (issocketio && strlen(sid) == 0) {
            analyzeRequest(timeoutMsec);
        }

        if (analyzeRequest(timeoutMsec)) {
#ifdef DEBUGGING
                Serial.println(F("Websocket established"));
#endif

                return true;

        } else {
            // Might just need to break until out of socket_client loop.
#ifdef DEBUGGING
            Serial.println(F("Invalid handshake"));
#endif
            disconnectStream();

            return false;
        }
    } else {
        return false;
    }
}

bool WebSocketClient::analyzeRequest(std::uint32_t timeoutMsec) {
    String temp = "";

    int bite;
    bool foundupgrade = false;
    bool foundsid = false;
    unsigned long intkey[2];
    String serverKey;
    char keyStart[17];
    char b64Key[25];
    String key = "------------------------";

    uint32_t recvMillis = millis();

    if (!issocketio || (issocketio && strlen(sid) > 0)) {

#ifdef DEBUGGING
    Serial.println(F("Sending websocket upgrade headers"));
#endif

#ifndef ARDUINO_ARCH_ESP32
        randomSeed(analogRead(0));
#endif

        for (int i=0; i<16; ++i) {
            keyStart[i] = (char)random(1, 256);
        }

        base64_encode(b64Key, keyStart, 16);

        for (int i=0; i<24; ++i) {
            key[i] = b64Key[i];
        }

        socket_client->print(F("GET "));
        socket_client->print(path);
        if (issocketio) {
            socket_client->print(F("socket.io/?EIO=3&transport=websocket&sid="));
            socket_client->print(sid);
        }
        socket_client->print(F(" HTTP/1.1\r\n"));
        socket_client->print(F("Upgrade: websocket\r\n"));
        socket_client->print(F("Connection: Upgrade\r\n"));
        socket_client->print(F("Sec-WebSocket-Key: "));
        socket_client->print(key);
        socket_client->print(CRLF);
        socket_client->print(F("Sec-WebSocket-Protocol: "));
        socket_client->print(protocol);
        socket_client->print(CRLF);
        socket_client->print(F("Sec-WebSocket-Version: 13\r\n"));

#ifdef DEBUGGING
        Serial.println("Printing websocket upgrade headers");
        Serial.print(F("GET "));
        Serial.print(path);
        if (issocketio) {
            socket_client->print(F("socket.io/?EIO=3&transport=websocket&sid="));
            socket_client->print(sid);
        }
        Serial.print(F(" HTTP/1.1\r\n"));
        Serial.print(F("Upgrade: websocket\r\n"));
        Serial.print(F("Connection: Upgrade\r\n"));
        Serial.print(F("Sec-WebSocket-Key: "));
        Serial.print(key);
        Serial.print(CRLF);
        Serial.print(F("Sec-WebSocket-Protocol: "));
        Serial.print(protocol);
        Serial.print(CRLF);
        Serial.print(F("Sec-WebSocket-Version: 13\r\n"));
#endif


    } else {

#ifdef DEBUGGING
    Serial.println(F("Sending socket.io session request headers"));
#endif

        socket_client->print(F("GET "));
        socket_client->print(path);
        socket_client->print(F("socket.io/?EIO=3&transport=polling HTTP/1.1\r\n"));
        socket_client->print(F("Connection: keep-alive\r\n"));
    }

    socket_client->print(F("Host: "));
    socket_client->print(host);
    socket_client->print(CRLF);
    socket_client->print(CRLF);

#ifdef DEBUGGING
    Serial.println(F("Analyzing response headers"));
#endif

    recvMillis = millis();

    Serial.print(F("Waiting"));
    while (!socket_client->available()) {
        if (!socket_client->connected()) {
            Serial.println();
            Serial.println("Connection diffused");
            return false;
        } else if ((millis() - recvMillis) > timeoutMsec) {
            socket_client->stop();
            Serial.println();
            Serial.println("Connection timeout");
            return false;
        }
        delay(100);
        Serial.print(".");
    }
    Serial.println();

    recvMillis = millis();

    while (true) {
        while((bite = socket_client->read()) == -1) {
            if (!socket_client->connected()) {
                Serial.println("Connection diffused");
                return false;
            } else if ((millis() - recvMillis) > socket_client->getTimeout()) {
                socket_client->stop();
                Serial.printf("Read timeout %lu\n", socket_client->getTimeout());
                return false;
            }
            delay(20);
        }
        recvMillis = millis();
        temp += (char)bite;

        if ((char)bite == '\n') {
            temp.trim();
            if (temp.length()==0) {
                // end of headers
                break;
            }
            String tempLC = temp;
            tempLC.toLowerCase(); // uses case-insensitive header string for parsing to ensure to catch response from servers using different upper/lowercase variants of headers
#ifdef DEBUGGING
            Serial.print("Got Header: " + temp);
#endif
            if (!foundupgrade && tempLC.startsWith("upgrade: websocket")) {
                foundupgrade = true;
            } else if (tempLC.startsWith("sec-websocket-accept: ")) {
                serverKey = temp.substring(22);
            } else if (!foundsid && tempLC.startsWith("set-cookie: ")) {
                 foundsid = true;
                 String tempsid;
                 if (temp.indexOf(";") == -1){ // looks for ";" in cookie header, which indicates more than one cookie value
                   tempsid = temp.substring(temp.indexOf("=") + 1);
                 }
                 else {
                   tempsid = temp.substring(temp.indexOf("=") + 1, temp.indexOf(";")); // assumes sid is first cookie value, discards all other values
                 }
                 strcpy(sid, tempsid.c_str());
                 #ifdef DEBUGGING
                    Serial.println("Parsing Set-Cookie...");
                    Serial.println("tempsid: " + tempsid);
                #endif
            }
            temp = "";
        }
    }

    if (issocketio && foundsid && !foundupgrade) {
        return true;
    }

    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t *hash;
    char result[21];
    char b64Result[30];

    Sha1.init();
    Sha1.print(key);
    hash = Sha1.result();

    for (int i=0; i<20; ++i) {
        result[i] = (char)hash[i];
    }
    result[20] = '\0';

    base64_encode(b64Result, result, 20);

    // if the keys match, good to go
    return serverKey.equals(String(b64Result));
}

WS_SIZE_T WebSocketClient::handleStream() {
    if (receivingFrame.state != WS_FRAME_OPCODE) {
        if ((millis() - receivingFrame._startMillis) > socket_client->getTimeout()) {
            // timeout
            receivingFrame.state = WS_FRAME_OPCODE;
            return -1;
        }
    }
    if (!socket_client->connected() || !socket_client->available()){
        return -1;
    } else if (receivingFrame.state == WS_FRAME_PAYLOAD) {
        return receivingFrame.frame.length-receivingFrame.index;
    }
    const int r = socket_client->read();
    if (r < 0) {
        return -1;
    }
    receivingFrame._startMillis = millis();
    switch(receivingFrame.state) {
        case WS_FRAME_OPCODE: {
            const uint8_t finOpcode = r;
            if ((finOpcode & WS_RSV) != 0) {
                // MUST be 0 unless an extension is negotiated that defines meanings
                // for non-zero values.  If a nonzero value is received and none of
                // the negotiated extensions defines the meaning of such a nonzero
                // value, the receiving endpoint MUST _Fail the WebSocket
                // Connection_.
            } else {
                receivingFrame.frame.fin = ((finOpcode & WS_FIN) != 0);
                receivingFrame.frame.opcode = finOpcode&(~WS_FIN);
                switch (receivingFrame.frame.opcode) {
                case WS_OPCODE_CONT:
                case WS_OPCODE_TEXT:
                case WS_OPCODE_BINARY:
                case WS_OPCODE_CLOSE:
                case WS_OPCODE_PING:
                case WS_OPCODE_PONG:
                    receivingFrame.state = WS_FRAME_LENGTH_8;
                    log_v("opcode: %d %x", receivingFrame.frame.fin, receivingFrame.frame.opcode);
                    break;
                default:
                    // If an unknown
                    // opcode is received, the receiving endpoint MUST _Fail the
                    // WebSocket Connection_.
                    break;
                }
            }
        } break;
        case WS_FRAME_LENGTH_8: {
            const uint8_t maskLen = r;
            receivingFrame.frame.hasMask = (bool)(maskLen & WS_MASK);
            const uint8_t len = maskLen & (~WS_MASK);
            receivingFrame.index = 0;
            if (len == WS_SIZE16) {
                receivingFrame.frame.length = 0;
                receivingFrame.state = WS_FRAME_LENGTH_16;
            } else if (len == WS_SIZE64) {
                receivingFrame.frame.length = 0;
                receivingFrame.state = WS_FRAME_LENGTH_64;
            } else {
                receivingFrame.frame.length = (WS_SIZE_T)len;
                if (receivingFrame.frame.hasMask) {
                    receivingFrame.state = WS_FRAME_MASK;
                } else {
                    receivingFrame.state = WS_FRAME_PAYLOAD;
                }
                log_v("length8: %d %u", receivingFrame.frame.hasMask, receivingFrame.frame.length);
            }
        } break;
        case WS_FRAME_LENGTH_16: {
            receivingFrame.frame.length = (receivingFrame.frame.length<<8 | (WS_SIZE_T)r);
            receivingFrame.index++;
            if (receivingFrame.index == 2) {
                receivingFrame.index = 0;
                if (receivingFrame.frame.hasMask) {
                    receivingFrame.state = WS_FRAME_MASK;
                } else {
                    receivingFrame.state = WS_FRAME_PAYLOAD;
                }
                log_v("length16: %d %u", receivingFrame.frame.hasMask, receivingFrame.frame.length);
            }
        } break;
        case WS_FRAME_LENGTH_64: {
            receivingFrame.frame.length = (receivingFrame.frame.length<<8 | (WS_SIZE_T)r);
            receivingFrame.index++;
            if (receivingFrame.index == 8) {
                receivingFrame.index = 0;
                if (receivingFrame.frame.hasMask) {
                    receivingFrame.state = WS_FRAME_MASK;
                } else {
                    receivingFrame.state = WS_FRAME_PAYLOAD;
                }
                log_v("length64: %d %u", receivingFrame.frame.hasMask, receivingFrame.frame.length);
            }
        } break;
        case WS_FRAME_MASK: {
            receivingFrame.frame.mask[receivingFrame.index++] = r;
            if (receivingFrame.index == 4) {
                receivingFrame.index = 0;
                receivingFrame.state = WS_FRAME_PAYLOAD;
                log_v("mask: %02x %02x %02x %02x", receivingFrame.frame.mask[0], receivingFrame.frame.mask[1], receivingFrame.frame.mask[2], receivingFrame.frame.mask[3]);
            }
        }
    }
    return -2;
}

bool WebSocketClient::getData(String& str, uint8_t *opcode) {
    const WS_SIZE_T remain = handleStream();
    if (remain == -2) {
      return false;
    } else if (0 <= remain) {
      char data[remain];
      const std::size_t len = getData(data, (std::size_t)remain, opcode);
      str += data;
      return len == remain;
    }
    return false;
}

std::size_t WebSocketClient::getData(char *data, std::size_t length, uint8_t *opcode) {
    if (!data || receivingFrame.state != WS_FRAME_PAYLOAD) {
        const WS_SIZE_T remain = handleStream();
        if (remain < 0) {
            return 0;
        } else if (!data) {
            return remain;
        } else if (receivingFrame.state != WS_FRAME_PAYLOAD) {
            return 0;
        }
    } else if (!socket_client->connected() || !socket_client->available()){
        return 0;
    }
    if (opcode != NULL) {
        *opcode = receivingFrame.frame.opcode;
    }
    const std::size_t len = socket_client->readBytes(data, length);
    if (receivingFrame.frame.hasMask) {
        // unmask the data
        for (int i=0; i<std::min(len, length); ++i) {
            data[i] = data[i] ^ receivingFrame.frame.mask[(receivingFrame.index++) % 4];
        }
    } else {
        // no mask
        receivingFrame.index += len;
    }
    log_v("data: %d %u %u %d", receivingFrame.frame.opcode, receivingFrame.frame.length, receivingFrame.index, len);
    if (receivingFrame.frame.length == receivingFrame.index) {
        // end
        receivingFrame.state = WS_FRAME_OPCODE;
    }
    receivingFrame._startMillis = millis();
    return length;
}

void WebSocketClient::disconnectStream() {
#ifdef DEBUGGING
    Serial.println(F("Terminating socket"));
#endif
    // Should send 0x8700 to server to tell it I'm quitting here.
    socket_client->write((uint8_t) 0x87);
    socket_client->write((uint8_t) 0x00);

    socket_client->flush();
    delay(10);
    socket_client->stop();
    strcpy(sid, "");
}

std::size_t WebSocketClient::sendData(const char *str, std::size_t size, uint8_t opcode) {
#ifdef DEBUGGING
    Serial.print(F("Sending data: "));
    Serial.println(str);
#endif
    if (socket_client->connected()) {
        uint8_t mask[4];
        int size_buf = size + 1;
        if (size > 125) {
            size_buf += 3;
        } else {
            size_buf += 1;
        }
        if (WS_MASK > 0) {
            size_buf += 4;
        }
        char buf[size_buf];
        char* p=buf;

        // Opcode; final fragment
        *p++ = (char)(opcode | WS_FIN);

        // NOTE: no support for > 16-bit sized messages
        if (size > 125) {
            *p++ = (char) (WS_SIZE16 | WS_MASK);
            *p++ = (char) (size >> 8);
            *p++ = (char) (size & 0xFF);
        } else {
            *p++ = (char) (size | WS_MASK);
        }

        if (WS_MASK > 0) {
            mask[0] = random(0, 256);
            mask[1] = random(0, 256);
            mask[2] = random(0, 256);
            mask[3] = random(0, 256);

            *p++ = (char) mask[0];
            *p++ = (char) mask[1];
            *p++ = (char) mask[2];
            *p++ = (char) mask[3];

            for (int i=0; i<size; ++i) {
                *p++ = str[i] ^ mask[i % 4];
            }
        } else {
            memcpy(p, str, size); p+=size;
        }
        *p++ = '\0';

        const std::size_t r = socket_client->write((uint8_t*)buf, size_buf);
        return r;
    }
    return 0;
}