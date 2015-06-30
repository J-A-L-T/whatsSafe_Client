require 'openssl'
class MessagesController < ApplicationController
  before_action :set_message, only: [:show, :edit, :update, :destroy]

  # GET /messages
  # GET /messages.json
  def index
    response = HTTParty.get('http://10.70.16.223:3001/'+$gUsername+'/message?timestamp='+Time.now.to_i.to_s+'&signature=signature',
    :headers => { 'Content-Type' => 'application/json' })
    body = JSON.parse(response.body)
    @message = body
  end

  # GET /messages/1
  # GET /messages/1.json
  def show
  end

  # GET /messages/new
  def new
    @message = Message.new
  end

  # GET /messages/1/edit
  def edit
  end

  # POST /messages
  # POST /messages.json
  def create
    @message = Message.new(message_params)

    pubkeyResponse = HTTParty.get('http://10.70.16.223:3001/'+@message.username+'/pubkey',
    :headers => { 'Content-Type' => 'application/json' })
    pubkeyBody = JSON.parse(pubkeyResponse.body)   
    pk = Base64.strict_decode64(pubkeyBody["pubkey_user"])
    pubkey_recipient = OpenSSL::PKey::RSA.new(pk)

    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.encrypt
    key_recipient = cipher.random_key
    iv = cipher.random_iv 

    encrypted_message = cipher.update(@message.message) + cipher.final

    key_recipient_enc = pubkey_recipient.public_encrypt key_recipient

    digest = OpenSSL::Digest::SHA256.new
    sig_recipient = $gPrivkey_user.sign digest, $gUsername + encrypted_message + iv + key_recipient_enc

    timestamp = Time.now.to_i

    data = $gUsername.to_s + encrypted_message.to_s + iv + key_recipient_enc.to_s + sig_recipient.to_s + timestamp.to_s + @message.username.to_s

    digest = OpenSSL::Digest::SHA256.new
    sig_service = $gPrivkey_user.sign digest, data

    response = HTTParty.post('http://10.70.16.223:3001/'+@message.username+'/message', 
    :body => { :outerMessage => { :timestamp => timestamp, 
                          :sig_service => Base64.strict_encode64(sig_service),
                          :sender => $gUsername, 
                          :cipher => Base64.strict_encode64(encrypted_message),
                          :iv => Base64.strict_encode64(iv),
                          :key_recipient_enc => Base64.strict_encode64(key_recipient_enc),
                          :sig_recipient => Base64.strict_encode64(sig_recipient)
                        }
             }.to_json,
    :headers => { 'Content-Type' => 'application/json' })

    redirect_to '/messages'
  end

  # PATCH/PUT /messages/1
  # PATCH/PUT /messages/1.json
  def update
    respond_to do |format|
      if @message.update(message_params)
        format.html { redirect_to @message, notice: 'Message was successfully updated.' }
        format.json { render :show, status: :ok, location: @message }
      else
        format.html { render :edit }
        format.json { render json: @message.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /messages/1
  # DELETE /messages/1.json
  def destroy
    @message.destroy
    respond_to do |format|
      format.html { redirect_to messages_url, notice: 'Message was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_message
      @message = Message.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def message_params
      params.require(:message).permit(:username, :message)
    end
end
