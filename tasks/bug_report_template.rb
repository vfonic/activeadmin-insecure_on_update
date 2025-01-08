# frozen_string_literal: true
require "bundler/inline"

gemfile(true) do
  source "https://rubygems.org"

  # Use `ACTIVE_ADMIN_PATH=. ruby tasks/bug_report_template.rb` to run
  # locally, otherwise run against the default branch.
  if ENV["ACTIVE_ADMIN_PATH"]
    gem "activeadmin", path: ENV["ACTIVE_ADMIN_PATH"], require: false
  else
    gem "activeadmin", github: "activeadmin/activeadmin", branch: "3-0-stable", require: false
  end

  # Change Rails version if necessary.
  gem "rails", "~> 7.2.0"

  gem "sprockets", "~> 3.7"
  gem "sassc-rails"
  gem "sqlite3", force_ruby_platform: true, platform: :mri
  gem "activerecord-jdbcsqlite3-adapter", platform: :jruby

  gem "activerecord-session_store"
  gem "devise"
  gem "pundit"

  # Fixes an issue on CI with default gems when using inline bundle with default
  # gems that are already activated
  # Ref: rubygems/rubygems#6386
  if ENV["CI"]
    require "net/protocol"
    require "timeout"

    gem "net-protocol", Net::Protocol::VERSION
    gem "timeout", Timeout::VERSION
  end
end

require "active_record"
require "action_controller/railtie"
require "action_view/railtie"
require "devise"
require "devise/orm/active_record"
require "active_admin"

# Add silence method to Logger
class Logger
  def silence(severity = Logger::ERROR)
    old_level = level
    self.level = severity
    yield
  ensure
    self.level = old_level
  end
end

ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
ActiveRecord::Base.logger = Logger.new(STDOUT)

ActiveRecord::Schema.define do
  create_table :active_admin_comments, force: true do |_t|
  end

  # Add sessions table for ActiveRecord store
  create_table :sessions do |t|
    t.string :session_id, null: false
    t.text :data
    t.timestamps
  end

  add_index :sessions, :session_id, unique: true
  add_index :sessions, :updated_at

  create_table :users, force: true do |t|
    t.string :full_name
    t.integer :manager_of_forum_id
    t.string :email
    t.string :encrypted_password
    t.string   :reset_password_token
    t.datetime :reset_password_sent_at
    t.datetime :remember_created_at
    t.timestamps
  end

  create_table :forums, force: true do |t|
    t.string :name
  end

  create_table :forum_threads, force: true do |t|
    t.string :title
    t.integer :forum_id
  end
end

# Add Session model for ActiveRecord store
class ActiveRecord::SessionStore::Session < ActiveRecord::Base
  attr_accessor :callback_called

  def self.data_column_size_limit
    65536
  end
end

class TestApp < Rails::Application
  config.root = __dir__
  config.hosts << ".example.com"

  # Use ActiveRecord session store instead of cookie store
  config.session_store :active_record_store,
    key: "cookie_store_key"

  config.secret_key_base = "secret_key_base"
  config.eager_load = false

  config.logger = Logger.new($stdout)
  Rails.logger = config.logger
end

class ApplicationController < ActionController::Base
  include Rails.application.routes.url_helpers
end

class ApplicationRecord < ActiveRecord::Base
  primary_abstract_class

  def self.ransackable_attributes(auth_object = nil)
    authorizable_ransackable_attributes
  end

  def self.ransackable_associations(auth_object = nil)
    authorizable_ransackable_associations
  end
end

class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
end

class Forum < ApplicationRecord
  has_many :forum_threads
end

class ForumThread < ApplicationRecord
  belongs_to :forum
end

Devise.setup do |config|
  # config.mailer_sender = "please-change-me-at-config-initializers-devise@example.com"
  config.case_insensitive_keys = [:email]
  config.strip_whitespace_keys = [:email]
  config.skip_session_storage = [:http_auth]
  config.stretches = Rails.env.test? ? 1 : 12
  # config.reconfirmable = true
  # config.expire_all_remember_me_on_sign_out = true
  # config.password_length = 6..128
  # config.email_regexp = /\A[^@\s]+@[^@\s]+\z/
  # config.reset_password_within = 6.hours
  # config.sign_out_via = :delete
end

ActiveAdmin.setup do |config|
  config.comments = false
  config.authorization_adapter = ActiveAdmin::PunditAdapter
  # Authentication disabled by default. Override if necessary.
  # config.authentication_method = false
  config.authentication_method = :authenticate_user!
  # config.current_user_method = false
  config.current_user_method = :current_user

  # Add these lines to configure logout behavior
  config.logout_link_path = :destroy_user_session_path
  # config.logout_link_method = :delete
end

class ApplicationPolicy
  attr_reader :user, :record

  def initialize(user, record)
    @user = user
    @record = record
  end

  # def scope = Pundit.policy_scope!(user, record.class)

  class Scope
    attr_reader :user, :scope

    def initialize(user, scope)
      @user = user
      @scope = scope
    end

    def resolve = scope
  end
end

class ActiveAdmin::PagePolicy < ApplicationPolicy
  def show? = true
end

class UserPolicy < ApplicationPolicy
  def index? = true

  class Scope < ::ApplicationPolicy::Scope
    def resolve
      scope.all
    end
  end
end

class ForumPolicy < ApplicationPolicy
  def index? = true

  class Scope < ::ApplicationPolicy::Scope
    def resolve
      scope.where(id: user.manager_of_forum_id)
    end
  end
end

class ForumThreadPolicy < ApplicationPolicy
  def index? = true
  def update? = record.forum_id == user.manager_of_forum_id
  def create? = record.forum_id == user.manager_of_forum_id

  class Scope < ::ApplicationPolicy::Scope
    def resolve
      scope.where(forum_id: user.manager_of_forum_id)
    end
  end
end

Rails.application.initialize!

ActiveAdmin.register_page "Dashboard" do
  menu priority: 1, label: proc { I18n.t("active_admin.dashboard") }
  content do
    "Test Me"
  end
end

ActiveAdmin.register User do
end

ActiveAdmin.register Forum do
end

ActiveAdmin.register ForumThread do
  permit_params :title, :forum_id
end

Rails.application.routes.draw do
  devise_for :users, ActiveAdmin::Devise.config
  ActiveAdmin.routes(self)
end

require "minitest/autorun"
require "rack/test"
require "rails/test_help"

# Replace this with the code necessary to make your test fail.
class BugTest < ActionDispatch::IntegrationTest
  include ::Warden::Test::Helpers
  Warden.test_mode!

  setup do
    @admin_forum = Forum.create! name: "Test Forum"
    @other_forum = Forum.create! name: "Other Forum"
    @user = User.create! email: "test@example.com", password: "password", full_name: "John Doe", manager_of_forum_id: @admin_forum.id
    login_as @user, scope: :user
  end

  teardown { Warden.test_reset! }

  def test_admin_cannot_see_forum_hes_not_manager_of
    get admin_forums_url

    assert_response :success
    assert_no_match @other_forum.name, response.body
  end

  def test_admin_can_create_forum_thread_for_a_forum_hes_manager_of
    assert_difference 'ForumThread.count' do
      post admin_forum_threads_url, params: {
        forum_thread: {
          title: "Test Thread",
          forum_id: @admin_forum.id
        }
      }
    end

    assert_not_nil ForumThread.find_by(title: "Test Thread", forum_id: @admin_forum.id)
  end

  def test_admin_cannot_create_forum_thread_for_a_forum_hes_not_manager_of
    assert_no_difference 'ForumThread.count' do
      post admin_forum_threads_url, params: {
        forum_thread: {
          title: "Test Thread",
          forum_id: @other_forum.id
        }
      }
    end

    assert_response :redirect # or :unauthorized depending on your authorization setup
    # Verify no thread was created for the other forum
    assert_nil ForumThread.find_by(forum_id: @other_forum.id)
  end

  def test_admin_cannot_transfer_forum_thread_to_a_forum_hes_not_manager_of
    @forum_thread = ForumThread.create!(title: "Test Thread", forum_id: @admin_forum.id)

    assert_no_difference 'ForumThread.count' do
      patch admin_forum_thread_url(@forum_thread), params: {
        forum_thread: {
          forum_id: @other_forum.id
        }
      }
    end

    assert_not_equal @forum_thread.reload.forum_id, @other_forum.id
  end

  private

  def app
    Rails.application
  end
end
