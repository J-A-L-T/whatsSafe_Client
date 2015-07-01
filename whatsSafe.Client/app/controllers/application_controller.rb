class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  $URL = "http://localhost:3001/"
  $gUsername = ""
  $gPubkey_user = ""
  $gPrivkey_user = ""
end
