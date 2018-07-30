/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
    bodyParser = require('body-parser'),
    config = require('config'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({verify: verifyRequestSignature}));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
    process.env.MESSENGER_APP_SECRET :
    config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
    (process.env.MESSENGER_VALIDATION_TOKEN) :
    config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
    (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
    config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
    (process.env.SERVER_URL) :
    config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
    console.error("Missing config values");
    process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === "PcN65K3XPEQFyhb09Ejb") {
        console.log("Validating webhook");
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.error("Failed validation. Make sure the validation tokens match.");
        res.sendStatus(403);
    }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
    var data = req.body;

    // Make sure this is a page subscription
    if (data.object == 'page') {

        // Iterate over each entry
        // There may be multiple if batched
        data.entry.forEach(function (pageEntry) {

            //I added this clause... there was an error.
            if (pageEntry.messaging) {
                var pageID = pageEntry.id;
                var timeOfEvent = pageEntry.time;

                // Iterate over each messaging event
                pageEntry.messaging.forEach(function (messagingEvent) {
                    if (messagingEvent.optin) {
                        receivedAuthentication(messagingEvent);
                    } else if (messagingEvent.message) {
                        receivedMessage(messagingEvent);
                    } else if (messagingEvent.delivery) {
                        receivedDeliveryConfirmation(messagingEvent);
                    } else if (messagingEvent.postback) {
                        receivedPostback(messagingEvent);
                    } else if (messagingEvent.read) {
                        receivedMessageRead(messagingEvent);
                    } else if (messagingEvent.account_linking) {
                        receivedAccountLink(messagingEvent);
                    } else {
                        console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                    }
                });
            }


        });

        // Assume all went well.
        //
        // You must send back a 200, within 20 seconds, to let us know you've
        // successfully received the callback. Otherwise, the request will time out.
        res.sendStatus(200);
    }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function (req, res) {
    var accountLinkingToken = req.query.account_linking_token;
    var redirectURI = req.query.redirect_uri;

    // Authorization Code should be generated per user by the developer. This will
    // be passed to the Account Linking callback.
    var authCode = "1234567890";

    // Redirect users to this URI on successful login
    var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

    res.render('authorize', {
        accountLinkingToken: accountLinkingToken,
        redirectURI: redirectURI,
        redirectURISuccess: redirectURISuccess
    });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
    var signature = req.headers["x-hub-signature"];

    if (!signature) {
        // For testing, let's log an error. In production, you should throw an
        // error.
        console.error("Couldn't validate the signature.");
    } else {
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET)
            .update(buf)
            .digest('hex');

        if (signatureHash != expectedHash) {
            throw new Error("Couldn't validate the request signature.");
        }
    }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger'
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
        "through param '%s' at %d", senderID, recipientID, passThroughParam,
        timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfMessage = event.timestamp;
    var message = event.message;

    console.log("Received message for user %d and page %d at %d with message:",
        senderID, recipientID, timeOfMessage);
    console.log(JSON.stringify(message));

    var isEcho = message.is_echo;
    var messageId = message.mid;
    var appId = message.app_id;
    var metadata = message.metadata;

    // You may get a text or attachment but not both
    var messageText = message.text;
    var messageAttachments = message.attachments;
    var quickReply = message.quick_reply;

    if (isEcho) {
        // Just logging message echoes to console
        console.log("Received echo for message %s and app %d with metadata %s",
            messageId, appId, metadata);
        return;
    } else if (quickReply) {
        var quickReplyPayload = quickReply.payload;
        console.log("Quick reply for message %s with payload %s",
            messageId, quickReplyPayload);

        sendTextMessage(senderID, "Quick reply tapped");
        return;
    }

    if (messageText) {

        /** If text includes bookid search  */
        if (messageText.includes('bookid')) {
            createBookLink(messageText, senderID);


        }

        /** If text includes bookname search*/
        else if (messageText.includes('bookname') || messageText.includes('Bookname')) {

            /** fetch bookname from message */
            var bookName = messageText.replace(/[^\w\s]/gi, '').toLowerCase().replace('bookname', '');


            /** Goodreads API - Search with the name of the book */
            request({
                uri: 'https://www.goodreads.com/search/index.xml?key=vIUb7NUUS3M9qUFE6JzObA&q=' + bookName + "&search_type=books&search%5Bfield%5D=title",
                method: 'GET'

            }, function (error, response, body) {
                if (!error && response.statusCode == 200) {
                    /** Check status code */

                    var parseString = require('xml2js').parseString;

                    parseString(body, function (err, result) {
                        var search = result['GoodreadsResponse']['search'];
                        var totalResults = search[0]["total-results"];


                        if (totalResults != 0) {

                            sendTextMessage(senderID, "Please select your book:");
                            var rs = search[0]["results"];
                            var work = (rs[0]["work"]);

                            /** Facebook allows me to create a button object with maximum 3 items.
                             *  So, by using for loop I created buttons separately. */


                            if (totalResults < 5) {
                                var bookCount = totalResults;
                            } else {
                                var bookCount = 5;
                            }

                            for (var i = 0; i < bookCount; i++) {

                                /** Parse book object and id from the Goodreads api response */
                                var book = work[i]["best_book"];
                                var b_id = (book[0]["id"][0]["_"]);

                                /** Create a button*/
                                var messageData = {
                                    recipient: {
                                        id: senderID
                                    },
                                    message: {
                                        attachment: {
                                            type: "template",
                                            payload: {
                                                template_type: "button",
                                                text: book[0]['title'][0] + " (" + book[0]['author'][0]['name'] + ") Id:"+b_id,
                                                buttons: [{
                                                    /**
                                                     * if you use messenger over facebook app, it doesn't take payload
                                                     * so I need to take from text with title.
                                                     */
                                                    type: "postback",
                                                    title: "bookid " + b_id,
                                                    payload: "bookid " + b_id,
                                                }]
                                            }
                                        }
                                    }
                                }
                                callSendAPI(messageData);

                            }

                        } else {
                            /** Erroneous response from Goodreads  */
                            //if there is no book with book name search.
                            noResult(senderID);
                        }

                    });

                } else {

                    console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
                }
            });


        } else {

            // If we receive a text message, check to see if it matches any special
            // keywords and send back the corresponding example. Otherwise, just echo
            // the text we received.
            switch (messageText.replace(/[^\w\s]/gi, '').trim().toLowerCase()) {
                case 'hello':
                case 'hi':
                    sendHiMessage(senderID);
                    break;

                case 'thanks':
                case 'thank you':
                    sendYourWelcomeMessage(senderID);
                    break;

                case 'image':
                    requiresServerURL(sendImageMessage, [senderID]);
                    break;

                case 'gif':
                    requiresServerURL(sendGifMessage, [senderID]);
                    break;

                case 'audio':
                    requiresServerURL(sendAudioMessage, [senderID]);
                    break;

                case 'video':
                    requiresServerURL(sendVideoMessage, [senderID]);
                    break;

                case 'file':
                    requiresServerURL(sendFileMessage, [senderID]);
                    break;

                case 'button':
                    sendButtonMessage(senderID);
                    break;

                case 'generic':
                    requiresServerURL(sendGenericMessage, [senderID]);
                    break;

                case 'receipt':
                    requiresServerURL(sendReceiptMessage, [senderID]);
                    break;

                case 'quick reply':
                    sendQuickReply(senderID);
                    break;

                case 'read receipt':
                    sendReadReceipt(senderID);
                    break;

                case 'typing on':
                    sendTypingOn(senderID);
                    break;

                case 'typing off':
                    sendTypingOff(senderID);
                    break;

                case 'account linking':
                    requiresServerURL(sendAccountLinking, [senderID]);
                    break;

                case 'add menu':
                    addMenu();
                    break;

                case 'remove menu':
                    removeMenu();
                    break;

                default:
                    sendReminderMessage(senderID);

            }

        }


    } else if (messageAttachments) {
        sendTextMessage(senderID, "Message with attachment received");
    }
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var delivery = event.delivery;
    var messageIDs = delivery.mids;
    var watermark = delivery.watermark;
    var sequenceNumber = delivery.seq;

    if (messageIDs) {
        messageIDs.forEach(function (messageID) {
            console.log("Received delivery confirmation for message ID: %s",
                messageID);
        });
    }

    console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfPostback = event.timestamp;

    // The 'payload' param is a developer-defined field which is set in a postback
    // button for Structured Messages.
    var payload = event.postback.payload;

    /**
     * messenger lite doesn't send payload postback!!!
     */
    console.log("Received postback for user %d and page %d with payload '%s' " +
        "at %d", senderID, recipientID, payload, timeOfPostback);

    // When a postback is called, we'll send a message back to the sender to
    // let them know it was successful

    //payload option for this bot

    /** Created Payload Options :
     *  1. Sample for search by id
     *  2. Sample for search by title
     *  3. Search book by its Goodreads id
     *  4. Get started
     *  5. Start bot
     * */

    if (payload == "search_by_id") {
        var mes = `Example:
bookid 25776195`;
        sendTextMessage(senderID, mes);
    } else if (payload == "search_by_name") {
        var mes = `Example:
bookname Extraordinary Mind`;
        sendTextMessage(senderID, mes);
    } else if (payload.includes('bookid') || payload.includes('Bookid')) {
        createBookLink(payload, senderID);
    } else if (payload == "GET_STARTED_PAYLOAD") {
        //Greetings when user start chat
        addMenu();
        greetings(senderID);
    } else if (payload == "start_bot") {
        //If user start chatbox again from menu
        greetings(senderID);
    }

    else {
        var mes = "Sorry I don't understand";
        sendTextMessage(senderID, mes);
    }


}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    // All messages before watermark (a timestamp) or sequence have been seen.
    var watermark = event.read.watermark;
    var sequenceNumber = event.read.seq;

    console.log("Received message read event for watermark %d and sequence " +
        "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    var status = event.account_linking.status;
    var authCode = event.account_linking.authorization_code;

    console.log("Received account link event with for user %d with status %s " +
        "and auth code %s ", senderID, status, authCode);
}

/*
 * If users came here through testdrive, they need to configure the server URL
 * in default.json before they can access local resources likes images/videos.
 */
function requiresServerURL(next, [recipientId, ...args]) {
    if (SERVER_URL === "to_be_set_manually") {
        var messageData = {
            recipient: {
                id: recipientId
            },
            message: {
                text: `
We have static resources like images and videos available to test, but you need to update the code you downloaded earlier to tell us your current server url.
1. Stop your node server by typing ctrl-c
2. Paste the result you got from running "lt —port 5000" into your config/default.json file as the "serverURL".
3. Re-run "node app.js"
Once you've finished these steps, try typing “video” or “image”.
        `
            }
        }

        callSendAPI(messageData);
    } else {
        next.apply(this, [recipientId, ...args]);
    }
}

/*
 * Send hi message.
 *
 */

function sendHiMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: `
Hi, welcome to Brain Valley Chat Bot.
You can search books with name or Goodreads id.
I will do analysis and give you feedback about books.
Don't forget to write your search option. 
Examples:
bookid 25776195
bookname Extraordinary Mind
`
        }
    }

    callSendAPI(messageData);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "image",
                payload: {
                    url: SERVER_URL + "/assets/rift.png"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "image",
                payload: {
                    url: SERVER_URL + "/assets/instagram_logo.gif"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "audio",
                payload: {
                    url: SERVER_URL + "/assets/sample.mp3"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "video",
                payload: {
                    url: SERVER_URL + "/assets/allofus480.mov"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a file using the Send API.
 *
 */
function sendFileMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "file",
                payload: {
                    url: SERVER_URL + "/assets/test.txt"
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText,
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: "This is test text",
                    buttons: [{
                        type: "web_url",
                        url: "https://www.oculus.com/en-us/rift/",
                        title: "Open Web URL"
                    }, {
                        type: "postback",
                        title: "Trigger Postback",
                        payload: "DEVELOPER_DEFINED_PAYLOAD"
                    }, {
                        type: "phone_number",
                        title: "Call Phone Number",
                        payload: "+16505551234"
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "generic",
                    elements: [{
                        title: "rift",
                        subtitle: "Next-generation virtual reality",
                        item_url: "https://www.oculus.com/en-us/rift/",
                        image_url: SERVER_URL + "/assets/rift.png",
                        buttons: [{
                            type: "web_url",
                            url: "https://www.oculus.com/en-us/rift/",
                            title: "Open Web URL"
                        }, {
                            type: "postback",
                            title: "Call Postback",
                            payload: "Payload for first bubble",
                        }],
                    }, {
                        title: "touch",
                        subtitle: "Your Hands, Now in VR",
                        item_url: "https://www.oculus.com/en-us/touch/",
                        image_url: SERVER_URL + "/assets/touch.png",
                        buttons: [{
                            type: "web_url",
                            url: "https://www.oculus.com/en-us/touch/",
                            title: "Open Web URL"
                        }, {
                            type: "postback",
                            title: "Call Postback",
                            payload: "Payload for second bubble",
                        }]
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
    // Generate a random receipt ID as the API requires a unique ID
    var receiptId = "order" + Math.floor(Math.random() * 1000);

    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "receipt",
                    recipient_name: "Peter Chang",
                    order_number: receiptId,
                    currency: "USD",
                    payment_method: "Visa 1234",
                    timestamp: "1428444852",
                    elements: [{
                        title: "Oculus Rift",
                        subtitle: "Includes: headset, sensor, remote",
                        quantity: 1,
                        price: 599.00,
                        currency: "USD",
                        image_url: SERVER_URL + "/assets/riftsq.png"
                    }, {
                        title: "Samsung Gear VR",
                        subtitle: "Frost White",
                        quantity: 1,
                        price: 99.99,
                        currency: "USD",
                        image_url: SERVER_URL + "/assets/gearvrsq.png"
                    }],
                    address: {
                        street_1: "1 Hacker Way",
                        street_2: "",
                        city: "Menlo Park",
                        postal_code: "94025",
                        state: "CA",
                        country: "US"
                    },
                    summary: {
                        subtotal: 698.99,
                        shipping_cost: 20.00,
                        total_tax: 57.67,
                        total_cost: 626.66
                    },
                    adjustments: [{
                        name: "New Customer Discount",
                        amount: -50
                    }, {
                        name: "$100 Off Coupon",
                        amount: -100
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "What's your favorite movie genre?",
            quick_replies: [
                {
                    "content_type": "text",
                    "title": "Action",
                    "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
                },
                {
                    "content_type": "text",
                    "title": "Comedy",
                    "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
                },
                {
                    "content_type": "text",
                    "title": "Drama",
                    "payload": "DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
                }
            ]
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
    console.log("Sending a read receipt to mark message as seen");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "mark_seen"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
    console.log("Turning typing indicator on");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_on"
    };

    callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
    console.log("Turning typing indicator off");

    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: "typing_off"
    };

    callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: "Welcome. Link your account.",
                    buttons: [{
                        type: "account_link",
                        url: SERVER_URL + "/authorize"
                    }]
                }
            }
        }
    };

    callSendAPI(messageData);
}

function handleMessage(sender_psid, received_message) {

    let response;

    // Check if the message contains text
    if (received_message.text) {

        // Create the payload for a basic text message
        response = {
            "text": `You sent the message: "${received_message.text}". Now send me an image!`
        }
    }

    // Sends the response message
    callSendAPI(sender_psid, response);
}


/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
    request({
        uri: 'https://graph.facebook.com/v2.6/me/messages',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var recipientId = body.recipient_id;
            var messageId = body.message_id;

            if (messageId) {
                console.log("Successfully sent message with id %s to recipient %s",
                    messageId, recipientId);
            } else {
                console.log("Successfully called Send API for recipient %s",
                    recipientId);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });
}

/**
 * Send greetings message to user
 * 1. Welcome the user by using their first name.
 */
function greetings(senderId) {
    request({
        uri: 'https://graph.facebook.com/' + senderId + '?fields=first_name&access_token=',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'GET'

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var obj = JSON.parse(body);
            var firstName = obj.first_name;
            var greetingsText = 'Welcome ' + firstName;

            sendTextMessage(senderId, greetingsText);
            console.log("Welcome message sent to: " + firstName);
            //After greetings ask question what do user want to do
            askQuestion(senderId);
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });

}

/**
 * 2. Ask the user if they want to search books by name or by ID (Goodreads ID).
 *
 */

function askQuestion(senderID) {
    var messageData = {
        recipient: {
            id: senderID
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: "Do you want to search books by name or by Goodreads ID?",
                    buttons: [
                        {
                            type: "postback",
                            title: "By Name",
                            payload: "search_by_name",
                        },
                        {
                            type: "postback",
                            title: "By ID",
                            payload: "search_by_id",
                        }
                    ]
                }
            }
        }
    }
    callSendAPI(messageData);
}

/**
 * 5. Retrieve the selected book’s reviews from Goodreads and use IBM Watson to do a semantic analysis for the most recent reviews.
 * Send book reviews url to get semantic analysis results from IBM Watson
 * Book targeted analysis results!
 *
 */

function IBMSentiment(ISBNId, senderID, bookId, bookTitle) {


    var NaturalLanguageUnderstandingV1 = require('watson-developer-cloud/natural-language-understanding/v1.js');
    var natural_language_understanding = new NaturalLanguageUnderstandingV1({
        'username': 'e953df22-be54-455d-9cff-1b49cd8f1c7d',
        'password': '7yeUwPKuSKBh',
        'version': '2018-03-16'
    });

    var parameters = {
        //I choose to analyse from recent 10 summary reviews page. There is an IBM Watson free account limit.
        //It is possible to do analysis for other pages, full reviews or use different analyse options like emotional analysis.
        'url': 'https://www.goodreads.com/api/reviews_widget_iframe?did=DEVELOPER_ID&amp;format=html&amp;isbn=' + ISBNId + '&amp;links=660&amp;review_back=fff&amp;stars=000&amp;text=000;text_only=true',
        'features': {
            'sentiment': {
                'targets': [
                    'book'
                ]
            }
        }
    };

    natural_language_understanding.analyze(parameters, function (err, response) {
        if (err) {
            console.log('error:', err);
            //IBM watson only support some languages now. So if there is any different language on the review page, it gives error.
            var suggestion = "Sorry, I couldn't analyse this book. In reviews there are different languages. IBM Watson doesn't support some languages. Please choose another one or visit Goodreads website:";
            var bookUrl = suggestion + "https://www.goodreads.com/book/show/" + bookId;
            sendTextMessage(senderID, bookUrl);
        }
        else {

            var sentimentResultStr = JSON.stringify(response, null, 2);
            console.log(sentimentResultStr);
            var sentimentResult = JSON.parse(sentimentResultStr);

            console.log(sentimentResult);

            var label = sentimentResult.sentiment.targets[0].label;
            var score = sentimentResult.sentiment.targets[0].score;

            //Send message about semantic analysis results
            if (label == "positive") {
                var suggestion = "This book has positive reviews. Score is " + score + ". Buy now: ";

            } else if (label == "negative") {
                var suggestion = "This book has negative reviews. Score is " + score + ". You can select another book or you can check this book: ";
            } else {
                //neutral option
                var suggestion = "This book's reviews are neutral. For details you can check from the link: ";
            }
            var bookUrl = bookTitle + '. ' + suggestion + "https://www.goodreads.com/book/show/" + bookId;
            sendTextMessage(senderID, bookUrl);

        }
    });

}


/**
 * Menu contains  :
 * - Start Chatbot button
 * - Search By ID Button
 * - Search By Title Button
 */

function addMenu() {

    request({
        url: 'https://graph.facebook.com/v2.6/me/messenger_profile',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'POST',
        json: {
            "persistent_menu": [
                {
                    "locale": "default",
                    "composer_input_disabled": false,
                    "call_to_actions": [
                        {
                            "title": "Start Chatbot",
                            "type": "postback",
                            "payload": "start_bot"
                        },
                        {
                            "title": "Search By ID",
                            "type": "postback",
                            "payload": "search_by_id"
                        },
                        {
                            "title": "Search By Name",
                            "type": "postback",
                            "payload": "search_by_name"
                        }

                    ]
                }
            ]
        }

    }, function (error, response, body) {
        console.log(response)
        if (error) {
            console.log('Error sending messages: ', error)
        } else if (response.body.error) {
            console.log('Error: ', response.body.error)
        }
    })

}

/**
 * Remove menu option
 *
 */

function removeMenu() {
    request({
        url: 'https://graph.facebook.com/v2.6/me/thread_settings',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'POST',
        json: {
            setting_type: "call_to_actions",
            thread_state: "existing_thread",
            call_to_actions: []
        }

    }, function (error, response, body) {
        console.log(response)
        if (error) {
            console.log('Error sending messages: ', error)
        } else if (response.body.error) {
            console.log('Error: ', response.body.error)
        }
    })
}

/**
 * Create Goodreads url by using bookID and check whether Goodreads ID exists or not.
 */

function createBookLink(messageText, senderID) {

    var bookId = messageText.replace(/[^\w\s]/gi, '').toLowerCase().replace('bookid', '').trim();

    request({
        uri: 'https://www.goodreads.com/book/show/' + bookId + '.json?key=vIUb7NUUS3M9qUFE6JzObA',
        method: 'GET'

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {

            findISBN(bookId, senderID);


        } else {
            var messageData = {
                recipient: {
                    id: senderID
                },
                message: {
                    text: `I couldn't find any book with this Goodreads ID. Please try again. `
                }
            }
            callSendAPI(messageData);
        }

    });

}


/**
 * Sends message if Goodreads API responses empty book list.
 *
 */
function noResult(recipientId) {

    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: `I couldn't find any book included this word. Please try again. `
        }
    }

    callSendAPI(messageData);

}


/**
 * If the message does not contain any special keyword,
 * I will show sample usage.
 */

function sendReminderMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: `
You can search books with name or Goodreads id.
Don't forget to write your search option. 
Examples:
bookid 25776195
bookname Extraordinary Mind
`
        }
    }

    callSendAPI(messageData);
}


/**
 *
 * The only way to reach Goodreads reviews is taking them via Goodreads widget.
 * API does not provide reviews directly. However, there might be different Reviews API method for only
 * whitelisted partner program.
 * In order to get reviews from review widget, I need an ISBN id.
 *
 * This function takes Goodreads bookid as parameters and fetches ISBN Id of the book.
 *
 */

function findISBN(bookId, senderID) {

    request({
            //uri: 'https://www.goodreads.com/book/show.json?id=' + bookId + '?key=vIUb7NUUS3M9qUFE6JzObA',
            uri: 'https://www.goodreads.com/book/show/' + bookId + '.json?key=vIUb7NUUS3M9qUFE6JzObA',
            method: 'GET'

        }, function (error, response, body) {
            if (!error && response.statusCode == 200) {

                var parseString = require('xml2js').parseString;

                parseString(body, function (err, result) {
                    var isbn13 = result['GoodreadsResponse']['book'][0]['isbn13'];
                    var reviewsCount = result['GoodreadsResponse']['book'][0]['work'][0]['reviews_count'][0]["_"];
                    var bookTitle = result['GoodreadsResponse']['book'][0]['title'];

                    /**There are some problems at Goodreads api results so I need to check some conditions! */

                    var bookTitleStr = JSON.stringify(bookTitle);
                    bookTitleStr = bookTitleStr.replace('["', '');
                    bookTitleStr = bookTitleStr.replace('"]', '');


                    if (isbn13 == "")  /**Some books don't have ISBN13 number in Goodreads.*/
                    {
                        var suggestion = "Sorry, this book doesn't have ISBN id. I couldn't find any review about this book.: "
                        var bookUrl = suggestion + "https://www.goodreads.com/book/show/" + bookId;
                        sendTextMessage(senderID, bookUrl);

                    } else if (reviewsCount == 0)  /**Some books don't have any reviews.*/
                    {
                        var suggestion = "Sorry, there is no review about this book, I couldn't analyse.: "
                        var bookUrl = suggestion + "https://www.goodreads.com/book/show/" + bookId;
                        sendTextMessage(senderID, bookUrl);

                    } else {
                        var isbn13Str = JSON.stringify(isbn13);
                        isbn13Str = isbn13Str.replace('["', '');
                        isbn13Str = isbn13Str.replace('"]', '');

                        //Control for ISBN id
                        //sendTextMessage(senderID, isbn13Str);

                        //Send IBM watson to semantic analysis
                        IBMSentiment(isbn13Str, senderID, bookId, bookTitleStr);
                    }

                })

            }
        }
    );


}


/**
 * Send your welcome message.
 *
 */

function sendYourWelcomeMessage(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: `
Your welcome.
`
        }
    }

    callSendAPI(messageData);
}


// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function () {
    console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
