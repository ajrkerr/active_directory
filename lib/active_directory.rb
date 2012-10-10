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

require 'net/ldap'

require 'active_directory/base.rb'
require 'active_directory/container.rb'
require 'active_directory/member.rb'

require 'active_directory/user.rb'
require 'active_directory/group.rb'
require 'active_directory/computer.rb'

require 'active_directory/field_type/password.rb'
require 'active_directory/field_type/binary.rb'
require 'active_directory/field_type/date.rb'
require 'active_directory/field_type/timestamp.rb'
require 'active_directory/field_type/dn_array.rb'
require 'active_directory/field_type/user_dn_array.rb'
require 'active_directory/field_type/group_dn_array.rb'
require 'active_directory/field_type/member_dn_array.rb'

module ActiveDirectory
  
  #Special Fields
  def self.special_fields
    @@special_fields
  end

  def self.special_fields= sp_fields
    @@special_fields = sp_fields
  end

  @@special_fields = {

    #All objects in the AD
    :Base => {
      :objectguid => :Binary,
      :whencreated => :Date,
      :whenchanged => :Date,
      :memberof => :DnArray,
    },

    #User objects
    :User => {
      :objectguid => :Binary,
      :whencreated => :Date,
      :whenchanged => :Date,
      :objectsid => :Binary,
      :msexchmailboxguid => :Binary,
      :msexchmailboxsecuritydescriptor => :Binary,
      :lastlogontimestamp => :Timestamp,
      :pwdlastset => :Timestamp,
      :accountexpires => :Timestamp,
      :memberof => :MemberDnArray,
    },

    #Group objects
    :Group => {
      :objectguid => :Binary,
      :whencreated => :Date,
      :whenchanged => :Date,
      :objectsid => :Binary,
      :memberof => :GroupDnArray,
      :member => :MemberDnArray,
    },

    #Computer objects
    :Computer => {
      :objectguid => :Binary,
      :whencreated => :Date,
      :whenchanged => :Date,
      :objectsid => :Binary,
      :memberof => :GroupDnArray,
      :member => :MemberDnArray,
    },
  }
end
