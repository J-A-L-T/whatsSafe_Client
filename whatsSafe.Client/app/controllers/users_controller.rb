require 'openssl' # Dokumentation dazu: http://ruby-doc.org/stdlib-2.0/libdoc/openssl/rdoc/OpenSSL.html
class UsersController < ApplicationController
  before_action :set_user, only: [:show, :update, :destroy]

  def index
    if $gUsername != ""
    @users=[]
    response = HTTParty.get($URL,
    :body => {},
    :headers => { 'Content-Type' => 'application/json' })
    response.each do |r|
    username = r["username"]
    user = User.new(:name => username)
      @users<<user
    end
        else
        respond_to do |format|
            format.html { redirect_to '/', alert: "Sie sind nicht eingeloggt." }
          end
        end
  end

  def logout
    $gUsername = ""
    $gPrivkey_user = ""
    $gPubkey_user = ""
    redirect_to '/'
  end

  def new
    if $gUsername != ""      
      redirect_to '/messages'
    else
      @user = User.new
    end
  end

  def create
    @user = User.new(user_params)
    success = true
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

      response = HTTParty.post($URL+'user', 
      :body => { :user => { :username => @user.name, 
                            :salt_masterkey => Base64.strict_encode64(salt_masterkey),
                            :pubkey_user => Base64.strict_encode64(public_key), 
                            :privkey_user_enc => Base64.strict_encode64(privkey_user_enc)
                          }
               }.to_json,
      :headers => { 'Content-Type' => 'application/json' })
      case response.code
        when 409
          @success = false
          respond_to do |format|
          format.html { redirect_to '/users/new', alert: "Benutzername bereits vergeben." }
          end
        end
      end
        if (params[:commit] == 'Einloggen' || 'Registrieren') && success == true
          response = HTTParty.get($URL+@user.name, 
          :headers => { 'Content-Type' => 'application/json' })
          case response.code
          when 404
            respond_to do |format|
            format.html { redirect_to '/users/new', alert: "Anmeldung fehlgeschlagen" }
          end
          else
          # Masterkey bilden mit passwort und saltmasterkey
          # Sachen lokal 
          $gUsername = @user.name
          password = @user.password
          jsonResponse = JSON.parse(response.body)
          salt_masterkey = Base64.strict_decode64(jsonResponse["salt_masterkey"])
          $gPubkey_user = Base64.strict_decode64(jsonResponse["pubkey_user"])
          privkey_user_enc = Base64.strict_decode64(jsonResponse["privkey_user_enc"])
          i = 10000
          digest = OpenSSL::Digest::SHA256.new
          masterkey = OpenSSL::PKCS5.pbkdf2_hmac(password, salt_masterkey, i, 256, digest)
          cipher = OpenSSL::Cipher.new('AES-128-ECB')
          cipher.decrypt
          cipher.key = masterkey
          begin
          $gPrivkey_user = OpenSSL::PKey::RSA.new(cipher.update(privkey_user_enc) + cipher.final)
          rescue OpenSSL::Cipher::CipherError
            $gUsername = ""
            $gPubkey_user = ""
            $gPrivkey_user = ""
            respond_to do |format|
            format.html { redirect_to '/users/new', alert: "Anmeldung fehlgeschlagen." }
            end
          end
          if (params[:commit] == 'Registrieren') && $gUsername != ""
            respond_to do |format|
            format.html { redirect_to '/messages', notice: "Registrierung erfolgreich." }
          end
          elsif (params[:commit] == 'Einloggen') && $gUsername != ""
              redirect_to '/messages'
          end
        end
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
