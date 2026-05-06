# `CAA` resource record.
#
# RFC 8659. RDATA fields:
#   - `flag`: unsigned 8-bit integer (0-255); only bit 7 (128, "issuer critical") is defined.
#   - `property_tag`: ASCII alphanumeric token (e.g. `issue`, `issuewild`, `iodef`).
#   - `property_value`: quoted character-string.
# Values are preserved as parsed; flag range and tag charset are not validated,
# consistent with other RR types in this library.
class DNS::Zone::RR::CAA < DNS::Zone::RR::Record

  REGEX_CAA_RDATA = %r{
    (?<flag>\d+)\s+
    (?<property_tag>[A-Za-z0-9]+)\s+
    "(?<property_value>#{DNS::Zone::RR::REGEX_STRING})"\s*
  }mx

  attr_accessor :flag, :property_tag, :property_value

  def dump
    parts = general_prefix
    parts << flag
    parts << property_tag
    parts << %Q{"#{property_value}"}
    parts.join(' ')
  end

  def load(string, options = {})
    rdata = load_general_and_get_rdata(string, options)
    return nil unless rdata

    captures = rdata.match(REGEX_CAA_RDATA)
    return nil unless captures

    @flag = captures[:flag].to_i
    @property_tag = captures[:property_tag]
    @property_value = captures[:property_value]
    self
  end

end
