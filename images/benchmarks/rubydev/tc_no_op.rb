# A unit test that tests nothing.
# Based on the unit test that Stripe used to benchmark gVisor:
# https://stripe.com/blog/fast-secure-builds-choose-two

require "test/unit"

class TestNoOp < Test::Unit::TestCase
  def test_noop
  end
end
