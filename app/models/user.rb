class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  # Enum for role
  enum role: { customer: 0, owner: 1 }

  # Validations
  validates :user_name, presence: true
end
