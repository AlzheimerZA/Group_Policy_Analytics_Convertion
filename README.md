# Group_Policy_Analytics_Convertion
The script will convert the exported Group Policy Analytics CSV file to Intune Windows 10 Customer Device Policy.
Added the function that will loop through all csv file in the c:\intuneps directory and create the respective JSON files and import it to Intune.
Create the directory C:\IntunePS and add all exported csv files here. Rename the CSV to what the Intune Policy name should be.
The script will only take values that support MDM
