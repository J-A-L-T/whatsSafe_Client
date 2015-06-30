require 'openssl' # Dokumentation dazu: http://ruby-doc.org/stdlib-2.0/libdoc/openssl/rdoc/OpenSSL.html
class UsersController < ApplicationController
  before_action :set_user, only: [:show, :edit, :update, :destroy]

  # GET /users
  # GET /users.json
  def index
    @users = User.all
  end

  # GET /users/1
  # GET /users/1.json
  def show
  end

  # GET /users/new
  def new
    @user = User.new
  end

  # GET /users/1/edit
  def edit
  end

  # POST /users
  # POST /users.json   
  def create
    @user = User.new(user_params)
    if params[:commit] == 'Registrieren'
      salt_masterkey = OpenSSL::Random.random_bytes 64
      i = 10000
      digest = OpenSSL::Digest::SHA256.new
      masterkey = OpenSSL::PKCS5.pbkdf2_hmac(@user.password, salt_masterkey, i, 256, digest)
      key = OpenSSL::PKey::RSA.new(2048)
      private_key = key.to_pem
      puts private_key
      public_key = key.public_key.to_pem
      cipher = OpenSSL::Cipher.new('AES-128-ECB')
      cipher.encrypt
      cipher.key = masterkey
      privkey_user_enc = cipher.update(private_key) + cipher.final

      response = HTTParty.post('http://10.70.16.223:3001/user', 
      :body => { :user => { :username => @user.name, 
                            :salt_masterkey => Base64.strict_encode64(salt_masterkey),
                            :pubkey_user => Base64.strict_encode64(public_key), 
                            :privkey_user_enc => Base64.strict_encode64(privkey_user_enc)
                          }
               }.to_json,
      :headers => { 'Content-Type' => 'application/json' })
      if response.code == 201
        # render json: {"Status" => "201 - created"}
      else
        # render json: {"Status" => "Error"}
    end
  end
    if params[:commit] == 'Einloggen' || 'Registrieren'
      response = HTTParty.get('http://10.70.16.223:3001/'+@user.name, 
      :headers => { 'Content-Type' => 'application/json' })
      # Masterkey bilden mit passwort und saltmasterkey
      # Sachen lokal ablegen
      password = @user.password
      jsonResponse = JSON.parse(response.body)
      salt_masterkey = Base64.strict_decode64(jsonResponse["salt_masterkey"])
      pubkey_user = Base64.strict_decode64(jsonResponse["pubkey_user"])
      privkey_user_enc = Base64.strict_decode64(jsonResponse["privkey_user_enc"])
      i = 10000
      digest = OpenSSL::Digest::SHA256.new
      masterkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt_masterkey, i, 256, digest)
      cipher = OpenSSL::Cipher.new('AES-128-ECB')
      cipher.decrypt
      cipher.key = masterkey
      privkey_user = cipher.update(privkey_user_enc) + cipher.final

      redirect_to '/messages'
  end

  # PATCH/PUT /users/1
  # PATCH/PUT /users/1.json
  def update
    respond_to do |format|
      if @user.update(user_params)
        format.html { redirect_to @user, notice: 'User was successfully updated.' }
        format.json { render :show, status: :ok, location: @user }
      else
        format.html { render :edit }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
    end
  end

  # DELETE /users/1
  # DELETE /users/1.json
  def destroy
    @user.destroy
    respond_to do |format|
      format.html { redirect_to users_url, notice: 'User was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def user_params
      params.require(:user).permit(:name, :password)
    end
end
