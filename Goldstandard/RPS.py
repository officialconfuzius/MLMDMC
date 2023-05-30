from random import randint

player = False

choices = ['rock','paper','scissors']
computer = choices[randint(0,2)]
while player == False:
    player = input("rock,paper or scissors? Enter q to quit! ")
    if player==computer:
        print("tie")
        player = False
        computer = choices[randint(0,2)]
    elif player == "rock":
        if computer == "paper":
            print("you lose!")
        elif computer == "scissors":
            print("you win")
        player = False
        computer = choices[randint(0,2)]
    elif player == "scissors":
        if computer == "paper":
            print("you win")
        elif computer == "rock":
            print("you lose")
        player = False
        computer = choices[randint(0,2)]
    elif player == "paper":
        if computer == "rock":
            print("you win")
        elif computer == "scissors":
            print("you lose")
        player = False
        computer = choices[randint(0,2)]
    elif player == "q":
        break
    else:
        player = False
        computer = choices[randint(0,2)]
