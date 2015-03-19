#-- license
#
#  Based on original code by Justin Mecham and James Hunt
#  at http://rubyforge.org/projects/activedirectory
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#++ license

module ActiveDirectory
	class User < Base
		include Member

		UAC_ACCOUNT_DISABLED = 0x0002
		UAC_NORMAL_ACCOUNT   = 0x0200 # 512
		UAC_PASSWORD_NEVER_EXPIRES = 0x10000 #65536

		def self.filter # :nodoc:
			Net::LDAP::Filter.eq(:objectClass,'user') & ~Net::LDAP::Filter.eq(:objectClass,'computer')
		end

		def self.required_attributes #:nodoc:
			{ :objectClass => ['top', 'organizationalPerson', 'person', 'user'] }
		end

		#
		# Try to authenticate the current User against Active Directory
		# using the supplied password. Returns false upon failure.
		#
		# Authenticate can fail for a variety of reasons, primarily:
		#
		# * The password is wrong
		# * The account is locked
		# * The account is disabled
		#
		# User#locked? and User#disabled? can be used to identify the
		# latter two cases, and if the account is enabled and unlocked,
		# Athe password is probably invalid.
		#
		def authenticate(password)
			return false if password.to_s.empty?

			auth_ldap = @@ldap.dup.bind_as(
				:filter => "(sAMAccountName=#{sAMAccountName})",
				:password => password
			)
		end

		#
		# Return the User's manager (another User object), depending on
		# what is stored in the manager attribute.
		#
		# Returns nil if the schema does not include the manager attribute
		# or if no manager has been configured.
		#
		def manager
			return nil if @entry.manager.nil?
			User.find_by_distinguishedName(@entry.manager.to_s)
		end

		#
		# Returns an array of Group objects that this User belongs to.
		# Only the immediate parent groups are returned, so if the user
		# Sally is in a group called Sales, and Sales is in a group
		# called Marketting, this method would only return the Sales group.
		#
		def groups
			@groups ||= Group.find(:all, :distinguishedname => @entry[:memberOf] )
		end

		#
		# Returns an array of User objects that have this
		# User as their manager.
		#
		def direct_reports
			return [] if @entry.directReports.nil?
			@direct_reports ||= User.find(:all, @entry.directReports)
		end

		#
		# Returns true if this account has been locked out
		# (usually because of too many invalid authentication attempts).
		#
		# Locked accounts can be unlocked with the User#unlock! method.
		#
		def locked?
			!lockoutTime.nil? && lockoutTime.to_i != 0
		end

		#
		# Returns true if this account has been disabled.
		#
		def disabled?
			userAccountControl.to_i & UAC_ACCOUNT_DISABLED != 0
		end

		#
		# Disables the account
		#
		def disable
			new_mask = userAccountControl.to_i | UAC_ACCOUNT_DISABLED
			update_attributes userAccountControl: new_mask.to_s
		end

		#
		# Enables the account
		#
		def enable
			new_mask = userAccountControl.to_i ^ UAC_ACCOUNT_DISABLED
			update_attributes userAccountControl: new_mask.to_s
		end


		#
		# Returns true if this account is expired.
		#
		def expired?
			!lockoutTime.nil? && lockoutTime.to_i != 0
		end

		#
		# Returns true if this account has a password that does not expire.
		#
		def password_never_expires?
			userAccountControl.to_i & UAC_PASSWORD_NEVER_EXPIRES != 0
		end

		#
		# Returns true if the user should be able to log in with a correct
		# password (essentially, their account is not disabled or locked
		# out).
		#
		def can_login?
			!disabled? && !locked?
		end

		#
		# Change the password for this account.
		#
		# This operation requires that the bind user specified in
		# Base.setup have heightened privileges. It also requires an
		# SSL connection.
		#
		# If the force_change argument is passed as true, the password will
		# be marked as 'expired', forcing the user to change it the next
		# time they successfully log into the domain.
		#
		def change_password(new_password, force_change = false)
			settings = @@settings.dup.merge({
				:port => 636,
				:encryption => { :method => :simple_tls }
			})

			ldap = Net::LDAP.new(settings)
			ldap.modify(
				:dn => distinguishedName,
				:operations => [
					[ :replace, :lockoutTime, [ '0' ] ],
					[ :replace, :unicodePwd, [ FieldType::Password.encode(new_password) ] ],
					[ :replace, :userAccountControl, [ UAC_NORMAL_ACCOUNT.to_s ] ],
					[ :replace, :pwdLastSet, [ (force_change ? '0' : '-1') ] ]
				]
			)
		end

		#
		# Unlocks this account.
		#
		def unlock!
			@@ldap.replace_attribute(distinguishedName, :lockoutTime, ['0'])
		end
	end
end
