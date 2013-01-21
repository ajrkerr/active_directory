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
	class Group < Base
		include Member

		def self.filter # :nodoc:
			Net::LDAP::Filter.eq(:objectClass,'group')
		end

		def self.required_attributes # :nodoc:
			{ :objectClass => [ 'top', 'group' ] }
		end

		def reload # :nodoc:
			@member_users_non_r  = nil
			@member_users_r      = nil
			@member_groups_non_r = nil
			@member_groups_r     = nil
			@groups              = nil
			super
		end

		#
		# Returns true if the passed User or Group object belongs to
		# this group. For performance reasons, the check is handled
		# by the User or Group object passed.
		#
		def has_member?(user)
			user.member_of?(self)
		end

		#
		# Add the passed User or Group object to this Group. Returns true if
		# the User or Group is already a member of the group, or if the operation
		# to add them succeeds.
		#
		def add(new_member)
			return false unless new_member.is_a?(User) || new_member.is_a?(Group)
			if @@ldap.modify(:dn => distinguishedName, :operations => [
				[ :add, :member, new_member.distinguishedName ]
			])
				return true
			else
				return has_member?(new_member)
			end
		end

		#
		# Remove a User or Group from this Group. Returns true if the User or
		# Group does not belong to this Group, or if the oepration to remove them
		# succeeds.
		#
		def remove(member)
			return false unless member.is_a?(User) || member.is_a?(Group)
			if @@ldap.modify(:dn => distinguishedName, :operations => [
				[ :delete, :member, member.distinguishedName ]
			])
				return true
			else
				return !has_member?(member)
			end
		end

		def has_members?
			begin
				return (@entry.member.nil? || @entry.member.empty?) ? false : true
			rescue NoMethodError
				return false
			end
		end

		#
		# Returns an array of all User objects that belong to this group.
		#
		# If the recursive argument is passed as false, then only Users who
		# belong explicitly to this Group are returned.
		#
		# If the recursive argument is passed as true, then all Users who
		# belong to this Group, or any of its subgroups, are returned.
		# 
		def member_users(recursive = false)
			return [] unless @entry.respond_to?(:member)
                        @member_users = User.find(:all, :distinguishedname => @entry.member).delete_if { |u| u.nil? }
                        if recursive then
                          self.member_groups.each do |group|
                            @member_users.concat(group.member_users(true))
                          end
                        end
                        return @member_users
		end

		#
		# Returns an array of all Group objects that belong to this group.
		#
		# If the recursive argument is passed as false, then only Groups that
		# belong explicitly to this Group are returned.
		#
		# If the recursive argument is passed as true, then all Groups that
		# belong to this Group, or any of its subgroups, are returned.
		# 
		def member_groups(recursive = false)
                        @member_groups ||= Group.find(:all, :distinguishedname => @entry.member).delete_if { |g| g.nil? }
                        if recursive then
                          self.member_groups.each do |group|
                            @member_groups.concat(group.member_groups(true))
                          end
                        end
                        return @member_groups
		end

		#
		# Returns an array of Group objects that this Group belongs to.
		#
		def groups
			return [] if memberOf.nil?
			@groups ||= Group.find(:all, :distinguishedname => @entry.memberOf).delete_if { |g| g.nil? }
		end
	end
end
