require 'dns/zone/test_case'

class RR_CAA_Test < DNS::Zone::TestCase

  def test_build_rr__caa
    rr = DNS::Zone::RR::CAA.new
    rr.label = 'example.com.'
    rr.flag = 0
    rr.property_tag = 'issue'
    rr.property_value = 'letsencrypt.org'

    assert_equal 'example.com. IN CAA 0 issue "letsencrypt.org"', rr.dump
  end

  def test_build_rr__caa_issuer_critical
    rr = DNS::Zone::RR::CAA.new
    rr.label = 'example.com.'
    rr.flag = 128
    rr.property_tag = 'issue'
    rr.property_value = 'ca.example.net'

    assert_equal 'example.com. IN CAA 128 issue "ca.example.net"', rr.dump
  end

  def test_load_rr__caa
    rr = DNS::Zone::RR::CAA.new.load('example.com. IN CAA 0 issue "letsencrypt.org"')
    assert_equal 'example.com.', rr.label
    assert_equal 'CAA', rr.type
    assert_equal 0, rr.flag
    assert_equal 'issue', rr.property_tag
    assert_equal 'letsencrypt.org', rr.property_value
  end

  def test_load_rr__caa_with_ttl
    rr = DNS::Zone::RR::CAA.new.load('example.com. 3600 IN CAA 0 issuewild ""')
    assert_equal 'example.com.', rr.label
    assert_equal '3600', rr.ttl
    assert_equal 0, rr.flag
    assert_equal 'issuewild', rr.property_tag
    assert_equal '', rr.property_value
  end

  def test_load_rr__caa_iodef
    rr = DNS::Zone::RR::CAA.new.load('example.com. IN CAA 0 iodef "mailto:security@example.com"')
    assert_equal 0, rr.flag
    assert_equal 'iodef', rr.property_tag
    assert_equal 'mailto:security@example.com', rr.property_value
  end

  # `issue` values may carry parameters delimited by `;`; ensure the comment
  # stripper doesn't truncate the value at the in-quote semicolon.
  def test_load_rr__caa_value_with_semicolon
    rr = DNS::Zone::RR::CAA.new.load('@ IN CAA 0 issue "ca.example.net; account=12345"')
    assert_equal 'ca.example.net; account=12345', rr.property_value
  end

  def test_load_rr__caa_missing_quotes_returns_nil
    rr = DNS::Zone::RR::CAA.new.load('example.com. IN CAA 0 issue letsencrypt.org')
    assert_nil rr
  end

  def test_load_rr__caa_missing_tag_returns_nil
    rr = DNS::Zone::RR::CAA.new.load('example.com. IN CAA 0 "letsencrypt.org"')
    assert_nil rr
  end

  def test_load_rr__caa_non_numeric_flag_returns_nil
    rr = DNS::Zone::RR::CAA.new.load('example.com. IN CAA bad issue "letsencrypt.org"')
    assert_nil rr
  end

end
