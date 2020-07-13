import csv

with open('test.csv', 'w', newline='') as file:
	writer = csv.writer(file)
	writer.writerow(["ID", "Date", "Start", "End", "Elapsed"])