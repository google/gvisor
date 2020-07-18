#!/usr/local/bin/ruby
#
# HTMLProofer checks for the gVisor website.
#
require 'html-proofer'

# NoOpenerCheck checks to make sure links with target=_blank include the
# rel=noopener attribute.
class NoOpenerCheck < ::HTMLProofer::Check
  def run
    @html.css('a').each do |node|
      link = create_element(node)
      line = node.line

      rel = link.respond_to?(:rel) ? link.rel.split(' ') : []

      if link.respond_to?(:target) && link.target == "_blank" && !rel.include?("noopener")
        return add_issue("You should set rel=noopener for links with target=_blank", line: line)
      end
    end
  end
end

def main()
  options = {
    :check_html => true,
    :check_favicon => true,
    :disable_external => true,
  }

  HTMLProofer.check_directories(ARGV, options).run
end

if __FILE__ == $0
  main
end
