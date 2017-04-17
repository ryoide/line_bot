class WebhookController < ApplicationController
  require 'line/bot'
  protect_from_forgery :except => [:callback, :is_validate_signature]
  
  CHANNEL_SECRET = '28227f54c66cb6e4dc7b1d2efc108bdb'
  CHANNEL_ACCESS_TOKEN = 'lw3F5SuOT2RZJZvCRZZxaDV5GkL5iqlvX0A36N2SBCcKWd+7BPQPOPP/1FYZpML+Slb1z+oC8ZMSWbgOaTN2iT3Or8/1uTnSp1NL+CxUVhaa1qotSfFzHzzYV4hlxte718al5eoLkL6z8HWgo3h5dwdB04t89/1O/w1cDnyilFU='
  # OUTBOUND_PROXY = '54.173.229.200'
  
  def callback
    # unless is_validate_signature
    #   render :nothing => true, status: 470
    # end
    body = request.body.read
    client ||= Line::Bot::Client.new { |config|
      config.channel_secret = CHANNEL_SECRET
      config.channel_token = CHANNEL_ACCESS_TOKEN
    }
    signature = request.env['HTTP_X_LINE_SIGNATURE']
    unless client.validate_signature(body, signature)
      error 400 do 'Bad Request' end
    end
    
    events = client.parse_events_from(body)
    events.each { |event|
      case event
      when Line::Bot::Event::Message
        # case event.type
        # when Line::Bot::Event::MessageType::Text
          message = {
            type: 'text',
            text: event.message['text']
          }
          client.reply_message(event['replyToken'], message)
        # when Line::Bot::Event::MessageType::Image, Line::Bot::Event::MessageType::Video
        #   response = client.get_message_content(event.message['id'])
        #   tf = Tempfile.open("content")
        #   tf.write(response.body)
        # end
      end
    }
    head :ok
  end
  
  private
  # LINEからのアクセスか確認.
  # 認証に成功すればtrueを返す。
  # ref) https://developers.line.me/bot-api/getting-started-with-bot-api-trial#signature_validation
  def is_validate_signature
    # signature = request.headers["X-LINE-ChannelSignature"]
    # http_request_body = request.raw_post
    # hash = OpenSSL::HMAC::digest(OpenSSL::Digest::SHA256.new, CHANNEL_SECRET, http_request_body)
    # signature_answer = Base64.strict_encode64(hash)
    # signature == signature_answer
    
  end
end
