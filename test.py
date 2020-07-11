file = open("control", "w+")
file.write("2")
run = True
while run:
	temp = file.read().strip("\n")
	if temp == "1":
		print("yuh")
	else:
		print("not yuh")
	file.seek(0)
	