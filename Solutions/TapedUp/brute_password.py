

solutionSpace = [['CommunicationSetup', 50, 4, 5],['Jungle', 60, 8, 8],['Village', 40, 4, 3],['PowderMagazine', 45, 7, 5],['ConcentrationCamp', 80, 9, 0],['Airport', 95, 9, 0]]

operationSpace = ['Wolf','OperationWolf']

keyspace = []
for i in operationSpace:
    for j in solutionSpace:
        keyspace.append(i+j[0]+str(j[1])+str(j[2])+str(j[3]))
        keyspace.append(i+j[0]+str(j[1])+str(j[3])+str(j[2]))

with open('/home/flk/Working/CyberSkills2019/Dev/Army CTF Challenge/keyspace','w') as f:
    for i in keyspace:
        f.write(i+'\n')
        

# $ for i in $(cat keyspace); do echo $i | wine insider.exe; done
