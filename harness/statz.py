import time

class Statz:

    def __init__(self):
        self.runs = 0
        self.start = time.time()

    def seconds(self):
        return time.time() - self.start

    def increment(self):
        self.runs = self.runs + 1

    def __repr__(self):
        velocity = self.runs / self.seconds()
        return "%0.1f runs / second.  %d total runs in %0.1fs" % (velocity, self.runs, self.seconds())