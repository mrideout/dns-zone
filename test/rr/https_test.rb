require 'dns/zone/test_case'

# HTTPS shares SVCB's presentation format and adds no code of its own, so the
# RDATA parsing and dumping cases (params, TTL, malformed input) are covered
# once in `svcb_test.rb`. Only what is specific to this subclass is tested here:
# that it reports and emits its own TYPE.
class RR_HTTPS_Test < DNS::Zone::TestCase

  def test_build_rr__https_alias_mode
    rr = DNS::Zone::RR::HTTPS.new
    rr.label = 'example.com.'
    rr.priority = 0
    rr.target = 'svc.example.net.'

    assert_equal 'example.com. IN HTTPS 0 svc.example.net.', rr.dump
  end

  def test_load_rr__https_alias_mode
    rr = DNS::Zone::RR::HTTPS.new.load('example.com. IN HTTPS 0 svc.example.net.')
    assert_equal 'example.com.', rr.label
    assert_equal 'HTTPS', rr.type
    assert_equal 0, rr.priority
    assert_equal 'svc.example.net.', rr.target
    assert_nil rr.params
  end

end
