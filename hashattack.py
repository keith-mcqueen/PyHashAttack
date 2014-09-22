__author__ = 'keith'

from Crypto.Hash.SHA import SHA1Hash
import argparse
import os
import random
import numpy as np
import math
import matplotlib.pyplot as plt
import datetime
import time


class HashAttack:
    def __init__(self):
        self.word_list_loc = None
        self.max_bits = 20
        self.repeat = 5
        self.bit_masks = {}
        self.attack = 'collision'

        self.parse_args()

    def parse_args(self):
        print 'Parsing arguments...'

        # create the argument parser
        parser = argparse.ArgumentParser(description='This program conducts a series of experiments to determine how '
                                                     'many attempts it takes to find a digest collision in a SHA-1 '
                                                     'hash.',
                                         add_help=True)

        # add an argument for the file containing the list of words to use for hashing
        # add an argument for the directory containing the wordlist files
        parser.add_argument('--word-list', help='the location of the word list file (may be a directory, in which case '
                                                'all files in the directory will be used for the word list',
                            required=True, action='store')

        # add an argument for the maximum number of bits (of the digest) to compare (default is ?)
        parser.add_argument('--max-bits', help='the maximum number of bits to test in the digest (default is 20)',
                            type=int, default=20, action='store')

        # add an argument for the number of times to repeat the experiment (default is ?)
        parser.add_argument('--repeat', help='the number of times to repeat the attack (default is 1)',
                            type=int, default=1, action='store')

        # add an argument for the type of attack (collision or pre-image)
        parser.add_argument('--attack', help='the kind of attack to launch (collision or preimage)',
                            choices=['collision', 'preimage'], action='store', required=True)

        # parse the arguments
        args = parser.parse_args()

        # get the word list file/directory
        self.word_list_loc = args.word_list
        if not os.path.exists(self.word_list_loc):
            raise Exception('Word list file ({}) does not exist'.format(self.word_list_loc))
        if os.path.isdir(self.word_list_loc):
            raise Exception('Word list must be a file')

        # save the max number of bits to check
        self.max_bits = args.max_bits

        # save the number of repeats
        self.repeat = args.repeat

        # save the kind of attack to perform
        self.attack = args.attack + '_attack'

    def collision_attack(self):
            # create the hash algorithm instance
            sha_1 = SHA1Hash()

            bits_range = np.arange(1, self.max_bits + 1, 1)
            theoretical_values = [math.pow(2, i/2.0) for i in bits_range]
            average_values = np.zeros(self.max_bits)

            # prepare the plot
            plt.xlabel('number of digest bits compared')
            plt.ylabel('number of attempts before collision')

            # plot the theoretical values
            plt.plot(bits_range, theoretical_values, 'b-', label='Theoretical Values')

            # load the file
            print 'Loading word list file: {}...'.format(self.word_list_loc)
            word_list = tuple(open(self.word_list_loc).read().split())

            # calculate the total work to be done
            total_work = float(self.repeat * self.max_bits)
            start_time = time.time()

            # repeat the experiment
            for i in range(self.repeat):
                attempts_by_bits = np.zeros(self.max_bits, dtype=np.int)

                # for each bit up to the maximum number of bits to test...
                for bits in bits_range:
                    # create a dictionary to store non-collisions for later checking
                    failed_attempts = {}

                     # output progress
                    self.report_progress(bits, failed_attempts, i, start_time, total_work, word_list)

                    collision = False

                    # while no collision
                    while not collision:
                        if len(failed_attempts) % 1000 == 0:
                            self.report_progress(bits, failed_attempts, i, start_time, total_work, word_list)

                        # make sure we haven't run out of words (safety valve to prevent infinite loop)
                        if len(failed_attempts) == len(word_list) - 1:
                            average_values[bits - 1] += len(failed_attempts)
                            break

                        # get a random string from the word list
                        word = random.choice(word_list)
                        if word in failed_attempts.values():
                            continue

                        # generate a digest for the random word
                        truncated_digest = '{0:b}'.format(int(sha_1.new(word).hexdigest(), 16))[:bits]

                        # see if the generated digest matches an existing digest
                        if truncated_digest in failed_attempts:
                            # we have a collision
                            collision = True

                            # record the number of attempts
                            # print 'we got a collision for {} bits with these words: {} and {} after {} tries'.\
                            #     format(bits, word, failed_attempts[truncated_digest], len(failed_attempts))
                            attempts_by_bits[bits - 1] = len(failed_attempts)
                            average_values[bits - 1] += len(failed_attempts)
                        else:
                            # add the truncated digest and the word to the failed attempts
                            failed_attempts[truncated_digest] = word

                # plot the number of attempts for this experiment
                plt.plot(bits_range, attempts_by_bits.copy(), 'r.')

            # finish computing the average_values
            plt.plot(bits_range, [n / self.repeat for n in average_values], 'go', label='Average Values')

            # show the plot
            plt.legend(loc='upper left', shadow=True)
            plt.show()

    def report_progress(self, bits, failed_attempts, i, start_time, total_work, word_list):
        progress = int((((i + 1) * bits) / total_work) * 100)
        d_time = datetime.timedelta(seconds=int(time.time() - start_time))
        print '\rRound {3: 2} of {4}; Bit {5: 2} of {6}; {8: 9,} of {9: 9,} words in {7}: [{0}{1}] {2}%'. \
            format('#' * progress,
                   '.' * (100 - progress),
                   progress,
                   i + 1,
                   self.repeat,
                   bits,
                   self.max_bits,
                   d_time,
                   len(failed_attempts),
                   len(word_list)),

    def preimage_attack(self):
            # create the hash algorithm instance
            sha_1 = SHA1Hash()

            bits_range = np.arange(1, self.max_bits + 1, 1)
            theoretical_values = [math.pow(2, i) for i in bits_range]
            average_values = np.zeros(self.max_bits)

            # prepare the plot
            plt.xlabel('number of digest bits compared')
            plt.ylabel('number of attempts before collision')

            # plot the theoretical values
            plt.plot(bits_range, theoretical_values, 'b-', label='Theoretical Values')

            # load the file
            print 'Loading word list file: {}...'.format(self.word_list_loc)
            word_list = tuple(open(self.word_list_loc).read().split())

            # calculate the total work to be done
            total_work = float(self.repeat * self.max_bits)
            start_time = time.time()

            # repeat the experiment
            for i in range(self.repeat):
                # get a random word from the word list
                original_word = random.choice(word_list)
                original_digest = '{0:b}'.format(int(sha_1.new(original_word).hexdigest(), 16))

                attempts_by_bits = np.zeros(self.max_bits, dtype=np.int)

                # for each bit up to the maximum number of bits to test...
                for bits in bits_range:
                    # keep track of failed attempts
                    failed_attempts = {}

                     # output progress
                    self.report_progress(bits, failed_attempts, i, start_time, total_work, word_list)

                    # for each word in the list...
                    for word in word_list:
                        # if the number of tries is a multiple of 1000, then update the progress
                        if len(failed_attempts) % 1000 == 0:
                            self.report_progress(bits, failed_attempts, i, start_time, total_work, word_list)

                        # if the current word *is* the original word, then skip it
                        if word == original_word:
                            continue

                        # generate a digest for the current word
                        truncated_digest = '{0:b}'.format(int(sha_1.new(word).hexdigest(), 16))[:bits]

                        # see if the generated digest matches an existing digest
                        if original_digest.startswith(truncated_digest):
                            # record the number of attempts
                            attempts_by_bits[bits - 1] = len(failed_attempts)
                            average_values[bits - 1] += len(failed_attempts)

                            # we got a collision, so break out of this loop
                            break
                        else:
                            # add the truncated digest and the word to the failed attempts
                            failed_attempts[truncated_digest] = word

                # plot the number of attempts for this experiment
                plt.plot(bits_range, attempts_by_bits.copy(), 'r.')

            # finish computing the average_values
            plt.plot(bits_range, [n / self.repeat for n in average_values], 'go', label='Average Values')

            # show the plot
            plt.legend(loc='upper left', shadow=True)
            plt.show()

if __name__ == '__main__':
    try:
        hash_attack = HashAttack()
        # hash_attack.collision_attack()
        getattr(hash_attack, hash_attack.attack)()
    except Exception, e:
        print e.message
        plt.show()