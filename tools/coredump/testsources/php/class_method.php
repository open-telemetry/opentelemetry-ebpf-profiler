<?php

class PrimeChecker
{
    public function isPrime($number)
    {
        if ($number <= 1) {
            return false;
        }
        if ($number == 2) {
            return true;
        }

        $x = sqrt($number);
        $x = floor($x);
        for ($i = 2; $i <= $x; ++$i) {
            if ($number % $i == 0) {
                return false;
            }
        }
        return true;
    }
}

while (true) {
    $checker = new PrimeChecker();
    $start = 0;
    $end = 1000000;
    for ($i = $start; $i <= $end; $i++) {
        if ($checker->isPrime($i)) {
            // keep busy
        }
    }
}
