#!/usr/bin/env ruby

class PrimeChecker
  def is_prime(n)
    if n < 2
      return false
    elsif n == 2
      return true
    end
  
    ((2..(Math.sqrt(n)))).each do |i|
      sleep 1 # sleep to ensure we get labels from blocks
      return false if n % i == 0
    end
    return true
  end
end

class Prime
  class Summer
    def sum_of_primes(n)
        sum_of_primes = 0
        x = 2
        while x < n
            if PrimeChecker.new.is_prime(x)
                sum_of_primes += x
            end
            x += 1
        end
        return sum_of_primes
    end
  end
end

class Looper
  def work
    loop do
      for i in 0..1000000 do
        puts i, Prime::Summer.new.sum_of_primes(i)
      end
    end
  end
end

Looper.new.work
