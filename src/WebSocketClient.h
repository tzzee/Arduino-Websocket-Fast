/*
Websocket-Arduino, a websocket implementation for Arduino
Copyright 2016 Brendan Hall

Based on previous implementations by
Copyright 2011 Brendan Hall
and
Copyright 2010 Ben Swanson
and
Copyright 2010 Randall Brewer
and
Copyright 2010 Oliver Smith

Some code and concept based off of Webduino library
Copyright 2009 Ben Combee, Ran Talbott

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

-------------
Now based off
http://www.whatwg.org/specs/web-socket-protocol/

- OLD -
Currently based off of "The Web Socket protocol" draft (v 75):
http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-75
*/


#ifndef WEBSOCKETCLIENT_H_
#define WEBSOCKETCLIENT_H_

#include <Arduino.h>
#include <Stream.h>
#include "String.h"
#include "Client.h"

// CRLF characters to terminate lines/handshakes in headers.
#define CRLF "\r\n"

// Amount of time (in ms) a user may be connected before getting disconnected
// for timing out (i.e. not sending any data to the server).
#define TIMEOUT_IN_MS 10000

// ACTION_SPACE is how many actions are allowed in a program. Defaults to
// 5 unless overwritten by user.
#ifndef CALLBACK_FUNCTIONS
#define CALLBACK_FUNCTIONS 1
#endif

// Don't allow the client to send big frames of data. This will flood the Arduinos
// memory and might even crash it.
#ifndef MAX_FRAME_LENGTH
#define MAX_FRAME_LENGTH 256
#endif

#define SIZE(array) (sizeof(array) / sizeof(*array))

// WebSocket protocol constants
// First byte
#define WS_FIN            0x80
#define WS_RSV            0b01110000
#define WS_OPCODE_CONT    0x00
#define WS_OPCODE_TEXT    0x01
#define WS_OPCODE_BINARY  0x02
#define WS_OPCODE_CLOSE   0x08
#define WS_OPCODE_PING    0x09
#define WS_OPCODE_PONG    0x0a
// Second byte
#define WS_MASK           0x80
//#define WS_MASK           0x00
#define WS_SIZE16         126
#define WS_SIZE64         127


#define WS_CLOSE_UNSUPPORTED "Unsupported WebSocket opcode"
#define WS_CLOSE_BAD_REQUEST "Bad Request"

typedef std::size_t WS_SIZE_T;

class WebSocketClient {
public:

    // Handle connection requests to validate and process/refuse
    // connections.
    bool handshake(Client &client, bool socketio = false, std::uint32_t timeoutMsec=10000);

    // Get data off of the stream
    std::size_t getData(char *data, std::size_t capacity, uint8_t *opcode = NULL);
    bool getData(String& data, uint8_t *opcode = NULL);

    // Write data to the stream
    std::size_t sendData(const char *str, std::size_t size, uint8_t opcode);
    std::size_t sendData(const String& str, uint8_t opcode) {
        return sendData(str.c_str(), str.length(), opcode);
    }

    WS_SIZE_T handleStream();

    bool issocketio;
    char *path;
    char *host;
    char *protocol;

private:
    Client *socket_client;
    // socket.io session id
    char sid[32];


    struct Frame{
        bool fin;
        uint8_t opcode;
        WS_SIZE_T length;
        uint8_t mask[4];
        bool hasMask;
    };
    enum FrameNextState {
        WS_FRAME_OPCODE,
        WS_FRAME_LENGTH_8,
        WS_FRAME_LENGTH_16,
        WS_FRAME_LENGTH_64,
        WS_FRAME_MASK,
        WS_FRAME_PAYLOAD,  
    };
    struct ReceivingFrame{
        FrameNextState state;
        Frame frame;
        WS_SIZE_T index;
        unsigned long _startMillis;
    } receivingFrame;

    const char *socket_urlPrefix;

    // Discovers if the client's header is requesting an upgrade to a
    // websocket connection.
    bool analyzeRequest(std::uint32_t timeoutMsec);

    // Disconnect user gracefully.
    void disconnectStream();
};



#endif
