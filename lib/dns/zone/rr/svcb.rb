# `SVCB` resource record.
#
# RFC 9460. `priority` 0 is AliasMode, anything else ServiceMode; `target` is the
# TargetName. `params` holds the SvcParams verbatim as one string, or `nil` when
# absent; they are not split into individual keys/values.
class DNS::Zone::RR::SVCB < DNS::Zone::RR::Record

  REGEX_SVCB_RDATA = %r{
    \A\s*
    (?<priority>\d+)\s+
    (?<target>#{DNS::Zone::RR::REGEX_DOMAINNAME}|\.{1})
    (?:\s+(?<params>\S[\s\S]*?))?
    \s*\z
  }mx

  attr_accessor :priority, :target, :params

  def dump
    parts = general_prefix
    parts << priority
    parts << target
    parts << params if params && !params.empty?
    parts.join(' ')
  end

  def load(string, options = {})
    rdata = load_general_and_get_rdata(string, options)
    return nil unless rdata

    captures = rdata.match(self.class::REGEX_SVCB_RDATA)
    return nil unless captures

    @priority = captures[:priority].to_i
    @target = captures[:target]
    @params = captures[:params]
    self
  end

end
