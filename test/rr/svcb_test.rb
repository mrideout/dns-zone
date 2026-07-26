require 'dns/zone/test_case'

class RR_SVCB_Test < DNS::Zone::TestCase

  def test_build_rr__svcb_alias_mode
    rr = DNS::Zone::RR::SVCB.new
    rr.label = 'example.com.'
    rr.priority = 0
    rr.target = 'foo.example.com.'

    assert_equal 'example.com. IN SVCB 0 foo.example.com.', rr.dump
  end

  def test_build_rr__svcb_service_mode
    rr = DNS::Zone::RR::SVCB.new
    rr.label = '_dns.example.com.'
    rr.priority = 1
    rr.target = 'dot.example.com.'
    rr.params = 'alpn=dot port=853'

    assert_equal '_dns.example.com. IN SVCB 1 dot.example.com. alpn=dot port=853', rr.dump
  end

  def test_load_rr__svcb_alias_mode
    rr = DNS::Zone::RR::SVCB.new.load('example.com. IN SVCB 0 foo.example.com.')
    assert_equal 'example.com.', rr.label
    assert_equal 'SVCB', rr.type
    assert_equal 0, rr.priority
    assert_equal 'foo.example.com.', rr.target
    assert_nil rr.params
  end

  def test_load_rr__svcb_service_mode
    rr = DNS::Zone::RR::SVCB.new.load('_dns.example.com. IN SVCB 1 dot.example.com. alpn=dot port=853')
    assert_equal '_dns.example.com.', rr.label
    assert_equal 1, rr.priority
    assert_equal 'dot.example.com.', rr.target
    assert_equal 'alpn=dot port=853', rr.params
  end

  def test_load_rr__svcb_with_ttl
    rr = DNS::Zone::RR::SVCB.new.load('example.com. 7200 IN SVCB 1 . alpn=h2')
    assert_equal '7200', rr.ttl
    assert_equal 1, rr.priority
    assert_equal '.', rr.target
    assert_equal 'alpn=h2', rr.params
  end

  # A quoted SvcParam value can contain spaces; params must survive verbatim.
  def test_load_rr__svcb_quoted_param_value
    rr = DNS::Zone::RR::SVCB.new.load('example.com. IN SVCB 1 . alpn="h2,h3" ipv4hint=192.0.2.1')
    assert_equal 1, rr.priority
    assert_equal '.', rr.target
    assert_equal 'alpn="h2,h3" ipv4hint=192.0.2.1', rr.params
  end

  def test_load_rr__svcb_valueless_param
    rr = DNS::Zone::RR::SVCB.new.load('example.com. IN SVCB 1 foo.example.com. no-default-alpn')
    assert_equal 'foo.example.com.', rr.target
    assert_equal 'no-default-alpn', rr.params
  end

  # Trailing whitespace after the RDATA should not leak into params.
  def test_load_rr__svcb_trailing_whitespace
    rr = DNS::Zone::RR::SVCB.new.load('example.com. IN SVCB 0 foo.example.com.   ')
    assert_equal 'foo.example.com.', rr.target
    assert_nil rr.params
  end

  def test_load_rr__svcb_non_numeric_priority_returns_nil
    rr = DNS::Zone::RR::SVCB.new.load('example.com. IN SVCB bad foo.example.com.')
    assert_nil rr
  end

  def test_load_rr__svcb_missing_target_returns_nil
    rr = DNS::Zone::RR::SVCB.new.load('example.com. IN SVCB 1')
    assert_nil rr
  end

end
