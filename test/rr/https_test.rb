require 'dns/zone/test_case'

class RR_HTTPS_Test < DNS::Zone::TestCase

  def test_build_rr__https_alias_mode
    rr = DNS::Zone::RR::HTTPS.new
    rr.label = 'example.com.'
    rr.priority = 0
    rr.target = 'svc.example.net.'

    assert_equal 'example.com. IN HTTPS 0 svc.example.net.', rr.dump
  end

  def test_build_rr__https_service_mode
    rr = DNS::Zone::RR::HTTPS.new
    rr.label = 'example.com.'
    rr.priority = 1
    rr.target = '.'
    rr.params = 'alpn="h2,h3" ipv4hint=192.0.2.1'

    assert_equal 'example.com. IN HTTPS 1 . alpn="h2,h3" ipv4hint=192.0.2.1', rr.dump
  end

  def test_load_rr__https_alias_mode
    rr = DNS::Zone::RR::HTTPS.new.load('example.com. IN HTTPS 0 svc.example.net.')
    assert_equal 'example.com.', rr.label
    assert_equal 'HTTPS', rr.type
    assert_equal 0, rr.priority
    assert_equal 'svc.example.net.', rr.target
    assert_nil rr.params
  end

  def test_load_rr__https_service_mode_own_target
    rr = DNS::Zone::RR::HTTPS.new.load('example.com. IN HTTPS 1 . alpn="h2,h3" port=8443')
    assert_equal 1, rr.priority
    assert_equal '.', rr.target
    assert_equal 'alpn="h2,h3" port=8443', rr.params
  end

  def test_load_rr__https_with_ttl
    rr = DNS::Zone::RR::HTTPS.new.load('www.example.com. 3600 IN HTTPS 1 . alpn=h2')
    assert_equal '3600', rr.ttl
    assert_equal 1, rr.priority
    assert_equal '.', rr.target
    assert_equal 'alpn=h2', rr.params
  end

  def test_load_rr__https_non_numeric_priority_returns_nil
    rr = DNS::Zone::RR::HTTPS.new.load('example.com. IN HTTPS bad .')
    assert_nil rr
  end

end
